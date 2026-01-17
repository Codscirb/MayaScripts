"""RVA Tools (RISC Visual Assets) - Maya PySide2 utility."""

from __future__ import annotations

import importlib
import json
import os
import random
import re
from datetime import datetime

import maya.cmds as cmds
import maya.mel as mel
import maya.OpenMayaUI as omui

_PYSIDE2_SPEC = importlib.util.find_spec("PySide2")
_PYSIDE6_SPEC = importlib.util.find_spec("PySide6")
if _PYSIDE2_SPEC:
    from PySide2 import QtCore, QtWidgets
    from shiboken2 import wrapInstance
elif _PYSIDE6_SPEC:
    from PySide6 import QtCore, QtWidgets
    from shiboken6 import wrapInstance
else:
    raise ModuleNotFoundError(
        "Neither PySide2 nor PySide6 is available. Install PySide or use a supported Maya version."
    )

WINDOW_TITLE = "RVA Tools"
WORKSPACE_CONTROL = "rvaToolsWorkspaceControl"
WINDOW_NAME = "rvaToolsWindow"
OPTIONVAR_EXPORT_DIR = "rvaToolsExportDir"
OPTIONVAR_UV_CHECKER = "rvaToolsUVCheckerEnabled"
VERSION_HISTORY = ["2025.03.08.4", "2025.03.08.3"]

NAME_REGEX = re.compile(r"^[A-Za-z0-9_]+$")
TRANSFORM_TOLERANCE = 1e-4


def _log(message: str) -> None:
    """Print a log message to the script editor."""
    print("[RVA Tools] {}".format(message))


def _safe_option_var_get(name: str, default):
    """Get a Maya optionVar value with a default fallback."""
    if cmds.optionVar(exists=name):
        return cmds.optionVar(q=name)
    return default


def _safe_option_var_set(name: str, value) -> None:
    """Set a Maya optionVar value."""
    if isinstance(value, bool):
        cmds.optionVar(iv=(name, int(value)))
    elif isinstance(value, int):
        cmds.optionVar(iv=(name, value))
    else:
        cmds.optionVar(sv=(name, value))


def _get_selected_transforms() -> list[str]:
    """Return selected transform nodes (full paths)."""
    selection = cmds.ls(sl=True, long=True, type="transform") or []
    return selection


def _generate_rva_code() -> int:
    """Generate a random 6-digit RVA code."""
    return random.randint(0, 0xFFFFFF)


def _ensure_rva_attrs(node: str) -> None:
    """Ensure RVA attributes exist on a transform."""
    if not cmds.attributeQuery("rva", node=node, exists=True):
        cmds.addAttr(node, longName="rva", attributeType="bool", defaultValue=False)
        cmds.setAttr("{}.rva".format(node), e=True, keyable=True)
    if not cmds.attributeQuery("rvaCode", node=node, exists=True):
        cmds.addAttr(node, longName="rvaCode", attributeType="long", defaultValue=0)
        cmds.setAttr("{}.rvaCode".format(node), e=True, keyable=True)


def tag_selected_as_rva() -> None:
    """Tag selected transforms as RVAs."""
    transforms = _get_selected_transforms()
    if not transforms:
        _log("No transforms selected to tag.")
        return
    for node in transforms:
        _ensure_rva_attrs(node)
        if cmds.getAttr("{}.rva".format(node)):
            continue
        cmds.setAttr("{}.rva".format(node), True)
        cmds.setAttr("{}.rvaCode".format(node), _generate_rva_code())
    _log("Tagged {} transform(s) as RVA.".format(len(transforms)))


def untag_selected() -> None:
    """Untag selected transforms (sets rva to False)."""
    transforms = _get_selected_transforms()
    if not transforms:
        _log("No transforms selected to untag.")
        return
    for node in transforms:
        if cmds.attributeQuery("rva", node=node, exists=True):
            cmds.setAttr("{}.rva".format(node), False)
    _log("Untagged {} transform(s).".format(len(transforms)))


def list_rva_roots() -> list[str]:
    """Return all RVA root transforms in the scene (full paths)."""
    transforms = cmds.ls(type="transform", long=True) or []
    rvas = []
    for node in transforms:
        if cmds.attributeQuery("rva", node=node, exists=True):
            try:
                if cmds.getAttr("{}.rva".format(node)):
                    rvas.append(node)
            except ValueError:
                continue
    return rvas


def select_all_rvas() -> None:
    """Select all RVA transforms in the scene."""
    rvas = list_rva_roots()
    cmds.select(rvas, r=True)
    _log("Selected {} RVA(s).".format(len(rvas)))


def _leaf_name(node: str) -> str:
    return node.split("|")[-1]


def _validate_name(name: str) -> bool:
    return bool(NAME_REGEX.match(name))


def _iter_mesh_shapes(root: str) -> list[str]:
    """Return mesh shapes under the RVA root."""
    return cmds.listRelatives(root, allDescendents=True, type="mesh", fullPath=True) or []



def _ensure_rva_material_attr(node: str) -> None:
    """Ensure a bool attribute 'rvaMaterial' exists on a shader/material node."""
    if not cmds.objExists(node):
        return
    if not cmds.attributeQuery("rvaMaterial", node=node, exists=True):
        try:
            cmds.addAttr(node, longName="rvaMaterial", attributeType="bool", defaultValue=False)
            cmds.setAttr(f"{node}.rvaMaterial", e=True, keyable=True)
        except Exception:
            # Some node types may disallow custom attrs; ignore.
            pass


def _is_rva_material(node: str) -> bool:
    if not cmds.objExists(node):
        return False
    if not cmds.attributeQuery("rvaMaterial", node=node, exists=True):
        return False
    try:
        return bool(cmds.getAttr(f"{node}.rvaMaterial"))
    except Exception:
        return False


def _iter_assigned_shaders(root: str) -> list[str]:
    """Return unique shader nodes assigned to meshes under root."""
    shaders = set()
    for mesh in _iter_mesh_shapes(root):
        shading_engines = cmds.listConnections(mesh, type="shadingEngine") or []
        shading_engines = [sg for sg in shading_engines if sg != "initialShadingGroup"]
        for sg in shading_engines:
            for sh in (cmds.listConnections(f"{sg}.surfaceShader") or []):
                if sh and sh != "lambert1":
                    shaders.add(sh)
    return sorted(shaders)


def _material_assignments_by_mesh(root: str) -> dict[str, dict[str, list[int]]]:
    """Return {mesh_shape: {material_name: [face_indices]}} assignments."""
    assignments = {}
    for mesh in _iter_mesh_shapes(root):
        face_count = cmds.polyEvaluate(mesh, face=True) or 0
        shading_engines = cmds.listConnections(mesh, type="shadingEngine") or []
        shading_engines = [sg for sg in shading_engines if sg != "initialShadingGroup"]
        material_faces = {}
        whole_mesh_materials = set()
        explicit_faces = set()

        for sg in shading_engines:
            materials = cmds.listConnections(f"{sg}.surfaceShader") or []
            materials = [m for m in materials if m and m != "lambert1"]
            if not materials:
                continue
            material = materials[0]
            faces, whole_objects = _expand_shading_engine_members(sg)
            mesh_faces = _faces_for_mesh(mesh, faces)
            if mesh_faces:
                material_faces.setdefault(material, set()).update(mesh_faces)
                explicit_faces.update(mesh_faces)
            else:
                parents = cmds.listRelatives(mesh, parent=True, fullPath=True) or []
                if mesh in whole_objects or (parents and parents[0] in whole_objects):
                    whole_mesh_materials.add(material)

        if whole_mesh_materials:
            remaining = set(range(face_count)) - explicit_faces
            for material in whole_mesh_materials:
                material_faces.setdefault(material, set()).update(remaining)

        assignments[mesh] = {
            material: sorted(indices)
            for material, indices in material_faces.items()
            if indices
        }
    return assignments


def _expand_shading_engine_members(sg: str) -> tuple[list[str], list[str]]:
    """Return (face_components, whole_object_members) for a shadingEngine set."""
    face_components = []
    whole_objects = []
    stack = list(cmds.sets(sg, q=True) or [])
    while stack:
        member = stack.pop()
        if not member or not cmds.objExists(member):
            continue
        if cmds.nodeType(member) == "objectSet":
            stack.extend(cmds.sets(member, q=True) or [])
            continue
        faces = cmds.filterExpand(member, selectionMask=34, expand=True) or []
        if faces:
            face_components.extend(faces)
        else:
            whole_objects.append(member)
    return face_components, whole_objects


def _faces_for_mesh(mesh: str, face_components: list[str]) -> list[int]:
    mesh_faces = []
    for face in face_components:
        if face.startswith(f"{mesh}.f["):
            match = re.search(r"\.f\[(\d+)\]$", face)
            if match:
                mesh_faces.append(int(match.group(1)))
    return mesh_faces


def _mesh_usd_name(mesh: str) -> str:
    parents = cmds.listRelatives(mesh, parent=True, fullPath=True) or []
    if parents:
        return _leaf_name(parents[0])
    return _leaf_name(mesh)


def _author_usd_material_subsets(usd_path: str, root: str) -> None:
    from pxr import Usd, UsdGeom, UsdShade

    assignments = _material_assignments_by_mesh(root)
    if not assignments:
        return

    stage = Usd.Stage.Open(usd_path)
    if not stage:
        _log(f"Unable to open USD stage for material subsets: {usd_path}")
        return

    material_prims = {}
    for prim in stage.Traverse():
        if prim.IsA(UsdShade.Material):
            material_prims[prim.GetName()] = prim

    materials_root = stage.GetPrimAtPath("/Materials")
    if not materials_root or not materials_root.IsValid():
        materials_root = stage.GetPrimAtPath("/Looks")
    if not materials_root or not materials_root.IsValid():
        materials_root = UsdGeom.Scope.Define(stage, "/Materials").GetPrim()

    rva_name = _leaf_name(root)

    for mesh, material_faces in assignments.items():
        if not material_faces:
            continue
        mesh_name = _mesh_usd_name(mesh)
        mesh_prim = stage.GetPrimAtPath(f"/{rva_name}/{mesh_name}")
        if not mesh_prim or not mesh_prim.IsA(UsdGeom.Mesh):
            mesh_prim = stage.GetPrimAtPath(f"/{mesh_name}")
        if not mesh_prim or not mesh_prim.IsA(UsdGeom.Mesh):
            for prim in stage.Traverse():
                if prim.IsA(UsdGeom.Mesh) and prim.GetName() == mesh_name:
                    mesh_prim = prim
                    break
        if not mesh_prim or not mesh_prim.IsA(UsdGeom.Mesh):
            _log(f"USD mesh prim not found for {mesh_name}.")
            continue

        usd_mesh = UsdGeom.Mesh(mesh_prim)
        for material_name, faces in material_faces.items():
            subset_name = _usd_safe_name(material_name)
            subset = UsdGeom.Subset.CreateGeomSubset(
                usd_mesh,
                subset_name,
                UsdGeom.Tokens.face,
                faces,
                familyName="materialBind",
            )
            subset.GetFamilyNameAttr().Set("materialBind")
            if subset_name != material_name:
                subset.GetPrim().SetMetadata("displayName", material_name)

            material_prim = material_prims.get(material_name) or material_prims.get(subset_name)
            if not material_prim or not material_prim.IsValid():
                material_path = materials_root.GetPath().AppendChild(subset_name)
                material_prim = stage.DefinePrim(material_path, "Material")
                material_prims[material_name] = material_prim
                material_prims[subset_name] = material_prim

            material = UsdShade.Material(material_prim)
            UsdShade.MaterialBindingAPI(subset.GetPrim()).Bind(material)

    stage.GetRootLayer().Save()


def _validate_rva_material_tags(root: str) -> list[dict]:
    """Fail if any mesh under root uses a shader that is not tagged as rvaMaterial."""
    issues = []
    offenders = []
    for mesh in _iter_mesh_shapes(root):
        shading_engines = cmds.listConnections(mesh, type="shadingEngine") or []
        shading_engines = [sg for sg in shading_engines if sg != "initialShadingGroup"]
        for sg in shading_engines:
            shaders = cmds.listConnections(f"{sg}.surfaceShader") or []
            shaders = [sh for sh in shaders if sh and sh != "lambert1"]
            for sh in shaders:
                if not _is_rva_material(sh):
                    offenders.append(mesh)
                    break
    if offenders:
        issues.append({
            "message": "Mesh uses non-RVA material (tag shader with rvaMaterial=True)",
            "nodes": sorted(set(offenders))
        })
    return issues


def _bake_and_lock_normals(mesh_shapes: list[str]) -> None:
    """Bake Maya shading (hard edges) into explicit vertex normals so USD writes primvars:normals."""
    for shape in mesh_shapes:
        if not cmds.objExists(shape):
            continue
        try:
            # Unlock normals
            cmds.polyNormalPerVertex(shape, unFreezeNormal=True)
            # Force explicit normals; keep artist-authored hard edges by freezing current normals
            cmds.polyNormalPerVertex(shape, freezeNormal=True)
        except Exception as e:
            _log(f"Failed baking normals on {shape}: {e}")


def _iter_mesh_transforms(root: str) -> list[str]:
    """Return transform parents of mesh shapes under the RVA root."""
    transforms = set()
    for mesh in _iter_mesh_shapes(root):
        parent = cmds.listRelatives(mesh, parent=True, fullPath=True) or []
        transforms.update(parent)
    return sorted(transforms)


def _validate_transforms(root: str) -> list[dict]:
    issues = []
    transforms = _iter_mesh_transforms(root)
    transforms.append(root)
    for node in transforms:
        translate = cmds.getAttr("{}.translate".format(node))[0]
        rotate = cmds.getAttr("{}.rotate".format(node))[0]
        scale = cmds.getAttr("{}.scale".format(node))[0]
        if any(abs(value) > TRANSFORM_TOLERANCE for value in translate):
            issues.append({"message": "Non-zero translate", "nodes": [node]})
        if any(abs(value) > TRANSFORM_TOLERANCE for value in rotate):
            issues.append({"message": "Non-zero rotate", "nodes": [node]})
        if any(abs(value - 1.0) > TRANSFORM_TOLERANCE for value in scale):
            issues.append({"message": "Non-one scale", "nodes": [node]})
    return issues


def _validate_history(root: str) -> list[dict]:
    issues = []
    for mesh in _iter_mesh_shapes(root):
        history = cmds.listHistory(mesh, pruneDagObjects=True) or []
        history = [node for node in history if node != mesh]
        deformers = [node for node in history if cmds.objectType(node, isType="geometryFilter")]
        offending = [node for node in history if node not in deformers]
        if offending:
            issues.append({"message": "Non-deformer history found", "nodes": [mesh]})
    return issues


def _validate_materials(root: str) -> list[dict]:
    issues = []
    for mesh in _iter_mesh_shapes(root):
        shading_engines = cmds.listConnections(mesh, type="shadingEngine") or []
        if not shading_engines:
            issues.append({"message": "Mesh has no shading assignment", "nodes": [mesh]})
            continue
        valid_shading = [sg for sg in shading_engines if sg != "initialShadingGroup"]
        if not valid_shading:
            issues.append({"message": "Mesh assigned to default material", "nodes": [mesh]})
            continue
        for sg in valid_shading:
            shaders = cmds.listConnections("{}.surfaceShader".format(sg)) or []
            if "lambert1" in shaders:
                issues.append({"message": "Mesh assigned to default material", "nodes": [mesh]})
                break
    return issues


def _validate_names_and_duplicates(rvas: list[str], root: str) -> list[dict]:
    issues = []
    root_name = _leaf_name(root)
    if not _validate_name(root_name):
        issues.append({"message": "Invalid RVA root name", "nodes": [root]})
    counts = {}
    for node in rvas:
        name = _leaf_name(node)
        counts[name] = counts.get(name, 0) + 1
    if counts.get(root_name, 0) > 1:
        issues.append({"message": "Duplicate RVA root name", "nodes": [root]})

    descendants = cmds.listRelatives(root, allDescendents=True, fullPath=True) or []
    for node in descendants:
        leaf = _leaf_name(node)
        if not _validate_name(leaf):
            issues.append({"message": "Invalid node name in hierarchy", "nodes": [node]})
    return issues


def validate_rva(root: str, rvas: list[str]) -> dict:
    """Validate a single RVA root. Returns dict with status, issues, offenders."""
    issues = []
    issues.extend(_validate_names_and_duplicates(rvas, root))
    issues.extend(_validate_history(root))
    issues.extend(_validate_materials(root))
    issues.extend(_validate_transforms(root))

    offenders = sorted({node for issue in issues for node in issue["nodes"]})
    return {
        "root": root,
        "pass": len(issues) == 0,
        "issues": issues,
        "offenders": offenders,
    }


def validate_rvas(rvas: list[str]) -> dict[str, dict]:
    """Validate all RVAs and return a map of root to validation result."""
    results = {}
    for root in rvas:
        results[root] = validate_rva(root, rvas)
    return results


def _polygon_counts(meshes: list[str]) -> dict:
    counts = {"meshes": len(meshes), "faces": 0, "triangles": 0, "vertices": 0}
    for mesh in meshes:
        counts["faces"] += cmds.polyEvaluate(mesh, face=True)
        counts["triangles"] += cmds.polyEvaluate(mesh, triangle=True)
        counts["vertices"] += cmds.polyEvaluate(mesh, vertex=True)
    return counts


def _ensure_export_settings() -> None:
    """Apply Unreal-friendly FBX export settings."""
    if not cmds.pluginInfo("fbxmaya", query=True, loaded=True):
        try:
            cmds.loadPlugin("fbxmaya")
        except RuntimeError:
            _log("FBX plugin not available; export settings may be incomplete.")
            return
    mel.eval("FBXResetExport;")
    mel.eval("FBXExportSmoothingGroups -v true;")
    mel.eval("FBXExportTangents -v true;")
    mel.eval("FBXExportSmoothMesh -v true;")
    mel.eval("FBXExportSkins -v false;")
    mel.eval("FBXExportShapes -v false;")
    mel.eval("FBXExportInputConnections -v false;")
    mel.eval("FBXExportEmbeddedTextures -v false;")
    if mel.eval('exists "FBXExportUnits"'):
        mel.eval("FBXExportUnits -v cm;")
    if mel.eval('exists "FBXExportUpAxis"'):
        mel.eval("FBXExportUpAxis z;")


def _ensure_usd_export_settings() -> bool:
    """Ensure USD export plugin is available."""
    if cmds.pluginInfo("mayaUsdPlugin", query=True, loaded=True):
        return True
    try:
        cmds.loadPlugin("mayaUsdPlugin")
        return True
    except RuntimeError:
        _log("USD plugin not available; USD export skipped.")
        return False


def export_rva(root: str, export_dir: str, validation: dict) -> str:
    """Export an RVA root to FBX and write JSON report. Returns FBX path."""
    _ensure_export_settings()
    rva_name = _leaf_name(root)
    fbx_path = os.path.join(export_dir, "{}.fbx".format(rva_name))
    report_path = os.path.join(export_dir, "{}_report.json".format(rva_name))
    selection = cmds.ls(sl=True, long=True) or []
    try:
        cmds.select(root, r=True)
        mel.eval('FBXExport -f "{}" -s;'.format(fbx_path.replace("\\", "/")))
    finally:
        cmds.select(selection, r=True)

    meshes = _iter_mesh_shapes(root)
    report = {
        "timestamp": datetime.now().isoformat(),
        "scene": cmds.file(q=True, sn=True),
        "rvaRoot": rva_name,
        "rvaCode": cmds.getAttr("{}.rvaCode".format(root)),
        "validation": {
            "pass": validation.get("pass"),
            "issues": [issue["message"] for issue in validation.get("issues", [])],
        },
        "exportPath": fbx_path,
        "polygonCounts": _polygon_counts(meshes),
    }
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    return fbx_path


def export_rva_usd(root: str, export_dir: str, *, bake_normals: bool = True, include_materials: bool = False) -> str:
    """Export an RVA root to USD. Returns USD path.

    bake_normals: writes explicit vertex normals so Unreal doesn't smooth everything.
    include_materials: exports assigned materials (allowed only if shaders are tagged rvaMaterial=True).
    """
    if not _ensure_usd_export_settings():
        return ""
    rva_name = _leaf_name(root)
    usd_path = os.path.join(export_dir, "{}.usd".format(rva_name))

    # Optionally enforce "official" materials only
    if include_materials:
        issues = _validate_rva_material_tags(root)
        if issues:
            _log("USD export blocked: non-RVA materials detected.")
            for issue in issues:
                _log(" - {}".format(issue["message"]))
            # Select offenders for quick fix
            offenders = []
            for issue in issues:
                offenders.extend(issue.get("nodes") or [])
            offenders = sorted(set(offenders))
            if offenders:
                cmds.select(offenders, r=True)
            return ""

    if bake_normals:
        _bake_and_lock_normals(_iter_mesh_shapes(root))

    # USD export options: keep polygonal mesh, no animation
    mats = 1 if include_materials else 0
    export_options = ";".join([
        "defaultMeshScheme=none",     # None (Polygonal Mesh)
        "animation=0",
        "stripNamespaces=1",
        "mergeTransformAndShape=1",
        "exportUVs=1",
        "exportColorSets=0",
        "exportDisplayColor=0",
        f"exportMaterials={mats}",
        f"exportAssignedMaterials={mats}",
    ]) + ";"

    selection = cmds.ls(sl=True, long=True) or []
    try:
        cmds.select(root, r=True)
        cmds.file(usd_path, force=True, options=export_options, type="USD Export", exportSelected=True)
    finally:
        if selection:
            cmds.select(selection, r=True)
        else:
            cmds.select(clear=True)
    if include_materials and usd_path and os.path.exists(usd_path):
        _author_usd_material_subsets(usd_path, root)
    return usd_path

import os
import re

def _usd_safe_name(name: str) -> str:
    n = re.sub(r"[^A-Za-z0-9_]+", "_", name.strip())
    n = re.sub(r"_+", "_", n).strip("_")
    return n or "Asset"

def _write_root_usda(root_usda_path: str, asset_names, include_materials: bool) -> None:
    lines = []
    lines.append("#usda 1.0\n")
    lines.append("(\n")
    lines.append('    defaultPrim = "World"\n')
    lines.append(")\n\n")
    lines.append('def Xform "World"\n{\n')
    lines.append('    def Xform "Geo"\n    {\n')

    for a in asset_names:
        lines.append(f'        def Xform "{a}" (\n')
        lines.append(f'            references = @./geo/{a}.usd@\n')
        lines.append("        )\n")
        lines.append("        {\n")
        lines.append("        }\n\n")

    lines.append("    }\n")

    if include_materials:
        lines.append('    def Xform "Materials" (\n')
        lines.append('        references = @./materials.usd@\n')
        lines.append("    )\n")
        lines.append("    {\n")
        lines.append("    }\n")

    lines.append("}\n")

    with open(root_usda_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

def build_usd_env(roots, export_dir: str, bake_normals: bool = True, include_materials: bool = False) -> str:
    """
    Builds:
      <export_dir>/usd_env/root.usda
      <export_dir>/usd_env/geo/<RVA>.usd   (one per RVA)
      <export_dir>/usd_env/materials.usd   (optional, if your export_rva_usd writes it when include_materials=True)
    Returns root.usda path.
    """
    env_dir = os.path.join(export_dir, "usd_env")
    geo_dir = os.path.join(env_dir, "geo")
    os.makedirs(geo_dir, exist_ok=True)

    asset_names = []
    for root in roots:
        asset_name = _usd_safe_name(root.split("|")[-1])

        # IMPORTANT:
        # We export each RVA into geo_dir so root.usda can reference ./geo/<name>.usd
        # Your export_rva_usd must write <geo_dir>/<asset_name>.usd (or we rename after).
        usd_path = export_rva_usd(
            root=root,
            export_dir=geo_dir,
            bake_normals=bake_normals,
            include_materials=include_materials
        )

        # If export_rva_usd returns a path with a different name, force it to match asset_name
        # so root references are stable.
        expected = os.path.join(geo_dir, f"{asset_name}.usd")
        try:
            if usd_path and os.path.normpath(usd_path) != os.path.normpath(expected) and os.path.exists(usd_path):
                # rename/move to expected
                if os.path.exists(expected):
                    os.remove(expected)
                os.rename(usd_path, expected)
        except Exception:
            pass

        asset_names.append(asset_name)

    # If your export path supports writing a materials.usd somewhere, do it here.
    # If you already have a "export tagged RVA materials to USD" function, call it here
    # and save to: os.path.join(env_dir, "materials.usd")
    if include_materials:
        # TODO: hook your existing RVA material export here if you have it.
        # Keep root referencing it regardless; Unreal will warn if missing.
        pass

    root_usda_path = os.path.join(env_dir, "root.usda")
    _write_root_usda(root_usda_path, asset_names, include_materials=include_materials)
    return root_usda_path



class RVAToolsUI(QtWidgets.QWidget):
    """Main UI for the RVA tool."""

    def __init__(self):
        super().__init__()
        self.setObjectName("rvaToolsWidget")
        self.validation_results: dict[str, dict] = {}
        self.last_export_paths: dict[str, str] = {}
        self.checker_assignments: dict[str, str] = {}
        self._last_offenders_by_root: dict[str, set[str]] = {}
        self._isolated_root: str | None = None
        self._build_ui()
        self.refresh_list()

    def _build_ui(self) -> None:
        main_layout = QtWidgets.QVBoxLayout()
        main_layout.setSpacing(6)
        self.setLayout(main_layout)

        self.rva_table = QtWidgets.QTableWidget(0, 5)
        self.rva_table.setHorizontalHeaderLabels(
            ["Root Name", "rvaCode", "Status", "Last Export", "Notes"]
        )
        self.rva_table.horizontalHeader().setStretchLastSection(True)
        self.rva_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.rva_table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.rva_table.itemSelectionChanged.connect(self._on_row_selected)

        tag_layout = QtWidgets.QHBoxLayout()
        tag_layout.addWidget(self._make_button("Tag Selected as RVA", self._tag_selected))
        tag_layout.addWidget(self._make_button("Untag Selected", self._untag_selected))
        tag_layout.addWidget(self._make_button("Select All RVAs", self._select_all))
        tag_layout.addWidget(self._make_button("Hide All RVAs", self._hide_all_rvas))
        tag_layout.addWidget(self._make_button("Show All RVAs", self._show_all_rvas))
        tag_layout.addWidget(self._make_button("Refresh List", self.refresh_list))

        mat_layout = QtWidgets.QHBoxLayout()
        mat_layout.addWidget(self._make_button("Tag Selected Materials as RVA", self._tag_selected_materials))
        mat_layout.addWidget(self._make_button("Untag Selected Materials", self._untag_selected_materials))
        mat_layout.addWidget(self._make_button("Select RVA Materials", self._select_rva_materials))


        validate_layout = QtWidgets.QHBoxLayout()
        validate_layout.addWidget(self._make_button("Validate Selected", self._validate_selected))
        validate_layout.addWidget(self._make_button("Validate All", self._validate_all))
        validate_layout.addWidget(self._make_button("Select Offenders", self._select_offenders))

        export_layout = QtWidgets.QHBoxLayout()
        self.export_dir_field = QtWidgets.QLineEdit()
        self.export_dir_field.setReadOnly(True)
        self.export_dir_field.setText(_safe_option_var_get(OPTIONVAR_EXPORT_DIR, ""))
        export_layout.addWidget(QtWidgets.QLabel("Export Dir:"))
        export_layout.addWidget(self.export_dir_field)
        export_layout.addWidget(self._make_button("Choose", self._choose_export_dir))
        export_layout.addWidget(self._make_button("Export Selected (FBX)", self._export_selected))
        export_layout.addWidget(self._make_button("Export All (FBX)", self._export_all))
        export_layout.addWidget(self._make_button("Export Selected (USD)", self._export_selected_usd))
        export_layout.addWidget(self._make_button("Export All (USD)", self._export_all_usd))
        export_layout.addWidget(self._make_button("Build USD Env (Selected)", self._build_usd_env_selected))
        export_layout.addWidget(self._make_button("Build USD Env (All)", self._build_usd_env_all))

        usd_opts_layout = QtWidgets.QHBoxLayout()
        self.usd_bake_normals_cb = QtWidgets.QCheckBox("USD: Bake & Lock Normals")
        self.usd_bake_normals_cb.setChecked(True)
        self.usd_include_materials_cb = QtWidgets.QCheckBox("USD: Include Materials (RVA-tagged only)")
        self.usd_include_materials_cb.setChecked(False)
        usd_opts_layout.addWidget(self.usd_bake_normals_cb)
        usd_opts_layout.addWidget(self.usd_include_materials_cb)
        usd_opts_layout.addStretch(1)


        utility_layout = QtWidgets.QHBoxLayout()
        utility_layout.addWidget(
            self._make_button(
                "Delete Non-Deformer History (Selected RVA)",
                self._delete_non_deformer_history,
            )
        )
        utility_layout.addWidget(
            self._make_button(
                "Freeze Transforms (Selected RVA)",
                self._freeze_transforms,
            )
        )

        self.uv_mapping_toggle = QtWidgets.QToolButton()
        self.uv_mapping_toggle.setText("UV Mapping")
        self.uv_mapping_toggle.setCheckable(True)
        self.uv_mapping_toggle.setChecked(False)
        self.uv_mapping_toggle.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        self.uv_mapping_toggle.setArrowType(QtCore.Qt.RightArrow)

        self.uv_mapping_frame = QtWidgets.QFrame()
        self.uv_mapping_frame.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.uv_mapping_frame.setVisible(False)
        uv_mapping_layout = QtWidgets.QVBoxLayout(self.uv_mapping_frame)
        uv_mapping_layout.setContentsMargins(20, 4, 4, 4)
        uv_mapping_layout.setSpacing(4)
        uv_mapping_layout.addWidget(
            QtWidgets.QLabel(
                "UV tools: auto UVs/unfold/orient, stack similar shells, or set 10cm density."
            )
        )
        uv_mapping_layout.addWidget(
            self._make_button("Auto Mapping", self._run_uv_auto_mapping)
        )
        uv_mapping_layout.addWidget(self._make_button("Stack UVs", self._run_uv_stacking))
        uv_mapping_layout.addWidget(self._make_button("Scale UVs", self._run_uv_scaling))

        self.uv_mapping_toggle.toggled.connect(self._toggle_uv_mapping_panel)

        view_layout = QtWidgets.QHBoxLayout()
        view_layout.addWidget(
            self._make_button("\u25c0", lambda: self._isolate_relative(-1), tooltip="Isolate previous RVA")
        )
        view_layout.addWidget(self._make_button("Isolate Selected RVA", self._isolate_selected))
        view_layout.addWidget(
            self._make_button("\u25b6", lambda: self._isolate_relative(1), tooltip="Isolate next RVA")
        )
        self.uv_checker_button = self._make_button("UV Checker Toggle", self._toggle_uv_checker)
        view_layout.addWidget(self.uv_checker_button)
        view_layout.addWidget(self._make_button("Show UV Overlap", self._show_uv_overlap))
        view_layout.addWidget(self._make_button("Geo Checks", self._run_geo_checks))

        self.results_box = QtWidgets.QPlainTextEdit()
        self.results_box.setReadOnly(True)
        self.results_box.setPlaceholderText("Validation results will appear here.")

        main_layout.addWidget(self.rva_table)
        main_layout.addLayout(tag_layout)
        main_layout.addLayout(mat_layout)
        main_layout.addSpacing(8)
        main_layout.addLayout(validate_layout)
        main_layout.addSpacing(8)
        main_layout.addLayout(export_layout)
        main_layout.addLayout(usd_opts_layout)
        main_layout.addSpacing(8)
        main_layout.addLayout(utility_layout)
        main_layout.addWidget(self.uv_mapping_toggle)
        main_layout.addWidget(self.uv_mapping_frame)
        main_layout.addLayout(view_layout)
        main_layout.addWidget(self.results_box)

        self._sync_uv_checker_state()

    def _uv_checker_enabled(self, meshes: list[str] | None = None) -> bool:
        sg_name = "rvaCheckerSG"
        if not cmds.objExists(sg_name):
            return False

        members = cmds.sets(sg_name, query=True) or []
        if not members:
            return False

        # Normalize members to long paths and strip components
        long_members = cmds.ls(members, long=True) or members
        member_shapes = {member.split(".")[0] for member in long_members}

        if meshes is None:
            return True

        long_meshes = cmds.ls(meshes, long=True) or meshes
        mesh_shapes = {mesh.split(".")[0] for mesh in long_meshes}
        return len(member_shapes.intersection(mesh_shapes)) > 0

    def _make_button(
        self, label: str, callback, tooltip: str | None = None
    ) -> QtWidgets.QPushButton:
        button = QtWidgets.QPushButton(label)
        button.clicked.connect(callback)
        button.setToolTip(tooltip or label)
        return button

    def _sync_uv_checker_state(self) -> None:
        enabled = self._uv_checker_enabled()
        self.uv_checker_button.setText("UV Checker On" if enabled else "UV Checker Off")

    def _toggle_uv_mapping_panel(self, checked: bool) -> None:
        self.uv_mapping_frame.setVisible(checked)
        self.uv_mapping_toggle.setArrowType(
            QtCore.Qt.DownArrow if checked else QtCore.Qt.RightArrow
        )

    def _current_root(self) -> str | None:
        # Keep isolate/UV checker behavior predictable: first selected row, else scene
        roots = self._selected_table_roots()
        if roots:
            return roots[0]
        return self._find_selected_rva()

    def _selected_table_roots(self) -> list[str]:
        """Return RVA roots selected in the table (column 0 UserRole)."""
        roots: list[str] = []
        sel = self.rva_table.selectionModel()
        if not sel:
            return roots

        for idx in sel.selectedRows(0):  # column 0
            item = self.rva_table.item(idx.row(), 0)
            if not item:
                continue
            root = item.data(QtCore.Qt.UserRole)
            if root:
                roots.append(root)

        return list(dict.fromkeys(roots))  # dedupe, preserve order

    def _find_selected_rva(self) -> str | None:
        """Legacy single-root finder (scene selection)."""
        selection = cmds.ls(sl=True, long=True, type="transform") or []
        if not selection:
            return None

        for node in selection:
            if cmds.attributeQuery("rva", node=node, exists=True):
                try:
                    if cmds.getAttr(f"{node}.rva"):
                        return node
                except ValueError:
                    pass

            parents = cmds.listRelatives(node, allParents=True, fullPath=True) or []
            for parent in parents:
                if cmds.attributeQuery("rva", node=parent, exists=True):
                    try:
                        if cmds.getAttr(f"{parent}.rva"):
                            return parent
                    except ValueError:
                        pass
        return None

    def _find_selected_rvas_from_scene(self) -> list[str]:
        """Find RVA root(s) based on current scene selection (supports selecting children/meshes)."""
        selection = cmds.ls(sl=True, long=True) or []
        if not selection:
            return []

        found: list[str] = []
        for node in selection:
            base = node.split(".")[0]
            if not cmds.objExists(base):
                continue

            # If user selected a shape/component, go to its transform
            if cmds.nodeType(base) != "transform":
                parents = cmds.listRelatives(base, parent=True, fullPath=True) or []
                if parents:
                    base = parents[0]

            # Walk up until we find an RVA-tagged transform
            cur = base
            while cur and cmds.objExists(cur):
                if cmds.nodeType(cur) == "transform" and cmds.attributeQuery("rva", node=cur, exists=True):
                    try:
                        if cmds.getAttr(f"{cur}.rva"):
                            found.append(cur)
                            break
                    except ValueError:
                        pass

                parents = cmds.listRelatives(cur, parent=True, fullPath=True) or []
                cur = parents[0] if parents else ""

        return list(dict.fromkeys(found))

    def _current_roots(self) -> list[str]:
        """
        Preferred: table selection (supports multi-select).
        Fallback: scene selection (supports selecting children).
        """
        roots = self._selected_table_roots()
        if roots:
            return roots

        scene_roots = self._find_selected_rvas_from_scene()
        if scene_roots:
            return scene_roots

        one = self._find_selected_rva()
        return [one] if one else []

    def _update_results_text(self, result: dict | None) -> None:
        if not result:
            self.results_box.setPlainText("No validation results.")
            return
        if result.get("pass"):
            self.results_box.setPlainText("Validation passed.")
            return
        lines = ["Validation failed:"]
        for issue in result.get("issues", []):
            nodes = ", ".join(issue.get("nodes", []))
            lines.append("- {} ({})".format(issue["message"], nodes))
        self.results_box.setPlainText("\n".join(lines))

    def _add_table_row(self, root: str) -> None:
        row = self.rva_table.rowCount()
        self.rva_table.insertRow(row)
        name_item = QtWidgets.QTableWidgetItem(_leaf_name(root))
        name_item.setData(QtCore.Qt.UserRole, root)
        if cmds.attributeQuery("rvaCode", node=root, exists=True):
            rva_code = cmds.getAttr("{}.rvaCode".format(root))
        else:
            rva_code = 0
        code_item = QtWidgets.QTableWidgetItem("0x{:06X}".format(rva_code))
        status_item = QtWidgets.QTableWidgetItem("Unknown")
        last_export = QtWidgets.QTableWidgetItem(self.last_export_paths.get(root, ""))
        notes_item = QtWidgets.QTableWidgetItem("")
        for item in (name_item, code_item, status_item, last_export, notes_item):
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
        self.rva_table.setItem(row, 0, name_item)
        self.rva_table.setItem(row, 1, code_item)
        self.rva_table.setItem(row, 2, status_item)
        self.rva_table.setItem(row, 3, last_export)
        self.rva_table.setItem(row, 4, notes_item)

    def refresh_list(self) -> None:
        self.rva_table.setRowCount(0)
        rvas = list_rva_roots()
        for root in rvas:
            self._add_table_row(root)
        self.validation_results = {}
        self.results_box.setPlainText("")
        _log("Refreshed RVA list ({} found).".format(len(rvas)))

    def _tag_selected(self) -> None:
        tag_selected_as_rva()
        self.refresh_list()

    def _untag_selected(self) -> None:
        untag_selected()
        self.refresh_list()


    def _tag_selected_materials(self) -> None:
        nodes = cmds.ls(sl=True) or []
        if not nodes:
            _log("Select one or more material/shader nodes to tag.")
            return
        tagged = 0
        for n in nodes:
            # If a shadingEngine is selected, tag its connected surface shader
            if cmds.nodeType(n) == "shadingEngine":
                shaders = cmds.listConnections(f"{n}.surfaceShader") or []
                for sh in shaders:
                    _ensure_rva_material_attr(sh)
                    try:
                        cmds.setAttr(f"{sh}.rvaMaterial", True)
                        tagged += 1
                    except Exception:
                        pass
                continue

            # If it's a mesh, tag its assigned shaders
            if cmds.objectType(n, isAType="shape") and cmds.nodeType(n) == "mesh":
                parent = cmds.listRelatives(n, parent=True, fullPath=True) or []
                targets = parent or [n]
                for t in targets:
                    for sh in _iter_assigned_shaders(t):
                        _ensure_rva_material_attr(sh)
                        try:
                            cmds.setAttr(f"{sh}.rvaMaterial", True)
                            tagged += 1
                        except Exception:
                            pass
                continue

            # Otherwise assume it's a shader/material node
            _ensure_rva_material_attr(n)
            if cmds.attributeQuery("rvaMaterial", node=n, exists=True):
                try:
                    cmds.setAttr(f"{n}.rvaMaterial", True)
                    tagged += 1
                except Exception:
                    pass

        _log(f"Tagged {tagged} material/shader node(s) as RVA materials.")

    def _untag_selected_materials(self) -> None:
        nodes = cmds.ls(sl=True) or []
        if not nodes:
            _log("Select one or more material/shader nodes to untag.")
            return
        untagged = 0
        for n in nodes:
            if cmds.nodeType(n) == "shadingEngine":
                shaders = cmds.listConnections(f"{n}.surfaceShader") or []
                for sh in shaders:
                    if cmds.attributeQuery("rvaMaterial", node=sh, exists=True):
                        try:
                            cmds.setAttr(f"{sh}.rvaMaterial", False)
                            untagged += 1
                        except Exception:
                            pass
                continue
            if cmds.attributeQuery("rvaMaterial", node=n, exists=True):
                try:
                    cmds.setAttr(f"{n}.rvaMaterial", False)
                    untagged += 1
                except Exception:
                    pass
        _log(f"Untagged {untagged} material/shader node(s).")

    def _select_rva_materials(self) -> None:
        mats = []
        for n in cmds.ls(materials=True) or []:
            if _is_rva_material(n):
                mats.append(n)
        # Some shaders won't appear in cmds.ls(materials=True); catch all with attribute
        for n in cmds.ls() or []:
            if _is_rva_material(n) and n not in mats:
                mats.append(n)
        if mats:
            cmds.select(sorted(set(mats)), r=True)
            _log(f"Selected {len(set(mats))} RVA material(s).")
        else:
            _log("No RVA materials found.")

    def _select_all(self) -> None:
        select_all_rvas()

    def _hide_all_rvas(self) -> None:
        rvas = list_rva_roots()
        if not rvas:
            _log("No RVAs found to hide.")
            return
        cmds.hide(rvas)
        _log("Hidden {} RVA(s).".format(len(rvas)))

    def _show_all_rvas(self) -> None:
        rvas = list_rva_roots()
        if not rvas:
            _log("No RVAs found to show.")
            return
        cmds.showHidden(rvas, all=True)
        _log("Shown {} RVA(s).".format(len(rvas)))

    def _on_row_selected(self) -> None:
        roots = self._selected_table_roots()
        if not roots:
            return
        cmds.select(roots, hi=True, r=True)
        # Show results for the first selected root
        self._update_results_text(self.validation_results.get(roots[0]))


    def _validate_selected(self) -> None:
        roots = self._current_roots()
        if not roots:
            _log("No RVA selected to validate.")
            return

        rvas = list_rva_roots()

        results: dict[str, dict] = {}
        for root in roots:
            result = validate_rva(root, rvas)
            results[root] = result
            self.validation_results[root] = result
            self._update_row_status(root, result)
            self._apply_validation_colors(root, result)
            self._print_validation_log(result)

        # UI summary: if only one, show its details; if many, show summary
        if len(roots) == 1:
            self._update_results_text(results[roots[0]])
        else:
            self._update_results_summary(results)

        _log("Validated {} RVA(s).".format(len(roots)))


    def _validate_all(self) -> None:
        rvas = list_rva_roots()
        if not rvas:
            _log("No RVAs found to validate.")
            self.results_box.setPlainText("No RVAs found to validate.")
            return
        results = validate_rvas(rvas)
        self.validation_results.update(results)
        for root, result in results.items():
            self._update_row_status(root, result)
            self._apply_validation_colors(root, result)
            self._print_validation_log(result)
        self._update_results_summary(results)
        _log("Validated {} RVA(s).".format(len(results)))

    def _update_row_status(self, root: str, result: dict) -> None:
        for row in range(self.rva_table.rowCount()):
            item = self.rva_table.item(row, 0)
            if item and item.data(QtCore.Qt.UserRole) == root:
                status_item = self.rva_table.item(row, 2)
                notes_item = self.rva_table.item(row, 4)
                status_item.setText("Pass" if result.get("pass") else "Fail")
                if result.get("pass"):
                    notes_item.setText("")
                else:
                    notes_item.setText("{} issue(s)".format(len(result.get("issues", []))))
                break

    def _print_validation_log(self, result: dict) -> None:
        if result.get("pass"):
            _log("Validation pass for {}".format(_leaf_name(result["root"])))
            return
        _log("Validation fail for {}:".format(_leaf_name(result["root"])))
        for issue in result.get("issues", []):
            _log("  - {} ({})".format(issue["message"], ", ".join(issue["nodes"])))

    def _expand_offenders(self, offenders: list[str]) -> list[str]:
        expanded: set[str] = set()

        def add_mesh_and_parent(mesh_shape: str) -> None:
            if not cmds.objExists(mesh_shape):
                return
            expanded.add(mesh_shape)
            parent = cmds.listRelatives(mesh_shape, parent=True, fullPath=True) or []
            for p in parent:
                expanded.add(p)

        def add_transform_and_meshes(xform: str) -> None:
            if not cmds.objExists(xform):
                return
            expanded.add(xform)
            shapes = (
                cmds.listRelatives(xform, allDescendents=True, type="mesh", fullPath=True) or []
            )
            for s in shapes:
                add_mesh_and_parent(s)

        for node in offenders:
            if not node:
                continue

            base = node.split(".")[0]

            if not cmds.objExists(base):
                continue

            if cmds.nodeType(base) == "mesh" or cmds.objectType(base, isAType="shape"):
                add_mesh_and_parent(base)
                continue

            if cmds.nodeType(base) == "transform":
                add_transform_and_meshes(base)
                continue

            expanded.add(base)

        return [n for n in sorted(expanded) if cmds.objExists(n)]

    def _set_outliner_color(self, nodes: list[str], color: tuple[float, float, float] | None) -> None:
        for node in nodes:
            if not cmds.objExists(node):
                continue
            if not cmds.attributeQuery("useOutlinerColor", node=node, exists=True):
                continue
            try:
                if color is None:
                    cmds.setAttr("{}.useOutlinerColor".format(node), False)
                else:
                    cmds.setAttr("{}.useOutlinerColor".format(node), True)
                    cmds.setAttr(
                        "{}.outlinerColor".format(node),
                        color[0],
                        color[1],
                        color[2],
                        type="double3",
                    )
            except RuntimeError:
                continue

    def _apply_validation_colors(self, root: str, result: dict) -> None:
        previous = self._last_offenders_by_root.get(root, set())
        current = set(self._expand_offenders(result.get("offenders", [])))
        reset_nodes = list(previous - current)
        if reset_nodes:
            self._set_outliner_color(reset_nodes, None)
        if current:
            self._set_outliner_color(list(current), (1.0, 0.2, 0.2))
        self._last_offenders_by_root[root] = current

    def _select_offenders(self) -> None:
        rvas = list_rva_roots()
        if not rvas:
            _log("No RVAs found to select offenders.")
            return

        results = validate_rvas(rvas)
        self.validation_results.update(results)
        all_offenders: list[str] = []
        for root, result in results.items():
            self._update_row_status(root, result)
            self._apply_validation_colors(root, result)
            all_offenders.extend(result.get("offenders", []))

        expanded = self._expand_offenders(all_offenders)
        if not expanded:
            _log("No offenders to select.")
            return

        try:
            cmds.select(expanded, r=True)
            _log("Selected {} offender node(s).".format(len(expanded)))
        except RuntimeError as e:
            _log("Selection warning: {}".format(e))
            safe = [n for n in expanded if cmds.objExists(n)]
            if safe:
                cmds.select(safe, r=True)

    def _choose_export_dir(self) -> None:
        directory = cmds.fileDialog2(dialogStyle=2, fileMode=3)
        if directory:
            export_dir = directory[0]
            self.export_dir_field.setText(export_dir)
            _safe_option_var_set(OPTIONVAR_EXPORT_DIR, export_dir)

    def _export_selected(self) -> None:
        roots = self._current_roots()
        if not roots:
            _log("No RVA selected to export.")
            return
        self._export_roots(roots)

    def _export_all(self) -> None:
        rvas = list_rva_roots()
        if not rvas:
            _log("No RVAs to export.")
            return
        self._export_roots(rvas)

    def _export_selected_usd(self) -> None:
        roots = self._current_roots()
        if not roots:
            _log("No RVA selected to export.")
            return
        self._export_roots_usd(roots)

    def _export_all_usd(self) -> None:
        rvas = list_rva_roots()
        if not rvas:
            _log("No RVAs to export.")
            return
        self._export_roots_usd(rvas)

    def _build_usd_env_selected(self) -> None:
        roots = self._current_roots()
        if not roots:
            _log("No RVA selected to build USD env.")
            return
        self._build_usd_env_from_roots(roots)

    def _build_usd_env_all(self) -> None:
        rvas = list_rva_roots()
        if not rvas:
            _log("No RVAs to build USD env.")
            return
        self._build_usd_env_from_roots(rvas)


    def _export_roots(self, roots: list[str]) -> None:
        export_dir = self.export_dir_field.text().strip()
        if not export_dir:
            _log("No export directory set.")
            return
        if not os.path.isdir(export_dir):
            _log("Export directory does not exist.")
            return


        all_rvas = list_rva_roots()
        results = {}
        for root in roots:
            results[root] = validate_rva(root, all_rvas)
        self.validation_results.update(results)
        failures = [root for root, result in results.items() if not result.get("pass")]
        if failures:
            _log("Export blocked due to validation failures.")
            for root in failures:
                self._update_row_status(root, results[root])
            return

        for root in roots:
            result = results[root]
            fbx_path = export_rva(root, export_dir, result)
            self.last_export_paths[root] = fbx_path
            self._update_row_status(root, result)
        self.refresh_list()
        _log("Export complete for {} RVA(s).".format(len(roots)))

    def _export_roots_usd(self, roots: list[str]) -> None:
        export_dir = self.export_dir_field.text().strip()
        if not export_dir:
            _log("No export directory set.")
            return
        if not os.path.isdir(export_dir):
            _log("Export directory does not exist.")
            return

        bake_normals = True
        include_materials = False
        try:
            bake_normals = bool(self.usd_bake_normals_cb.isChecked())
            include_materials = bool(self.usd_include_materials_cb.isChecked())
        except Exception:
            pass


        all_rvas = list_rva_roots()
        results = {}
        for root in roots:
            results[root] = validate_rva(root, all_rvas)
        self.validation_results.update(results)
        failures = [root for root, result in results.items() if not result.get("pass")]
        if failures:
            _log("Export blocked due to validation failures.")
            for root in failures:
                self._update_row_status(root, results[root])
            return

        for root in roots:
            result = results[root]
            usd_path = export_rva_usd(root, export_dir, bake_normals=bake_normals, include_materials=include_materials)
            if usd_path:
                self.last_export_paths[root] = usd_path
            self._update_row_status(root, result)
        self.refresh_list()
        _log("USD export complete for {} RVA(s).".format(len(roots)))

    def _build_usd_env_from_roots(self, roots) -> None:
        export_dir = self.export_dir_field.text().strip()
        if not export_dir:
            _log("No export directory set.")
            return

        bake_normals = True
        include_materials = False
        try:
            bake_normals = bool(self.usd_bake_normals_cb.isChecked())
            include_materials = bool(self.usd_include_materials_cb.isChecked())
        except Exception:
            pass

        root_path = build_usd_env(
            roots=roots,
            export_dir=export_dir,
            bake_normals=bake_normals,
            include_materials=include_materials,
        )

        _log(f"USD Env root written: {root_path}")

    def _delete_non_deformer_history(self) -> None:
        roots = self._current_roots()
        if not roots:
            _log("No RVA selected for delete history.")
            return

        for root in roots:
            try:
                cmds.bakePartialHistory(root, prePostDeformers=True)
                _log("Deleted non-deformer history for {}".format(_leaf_name(root)))
            except RuntimeError as e:
                _log("Delete history failed for {}: {}".format(_leaf_name(root), e))


    def _freeze_transforms(self) -> None:
        roots = self._current_roots()
        if not roots:
            _log("No RVA selected for freeze transforms.")
            return

        for root in roots:
            try:
                targets = _iter_mesh_transforms(root)
                targets.append(root)
                cmds.makeIdentity(targets, apply=True, t=1, r=1, s=1, n=0, pn=1)
                _log("Froze transforms for {}".format(_leaf_name(root)))
            except RuntimeError as e:
                _log("Freeze failed for {}: {}".format(_leaf_name(root), e))


    def _find_model_panel(self) -> str | None:
        panel = cmds.getPanel(withFocus=True)
        if panel and cmds.getPanel(typeOf=panel) == "modelPanel":
            return panel

        for p in (cmds.getPanel(vis=True) or []):
            if cmds.getPanel(typeOf=p) == "modelPanel":
                return p

        panels = cmds.getPanel(type="modelPanel") or []
        return panels[0] if panels else None


    def _frame_in_panel(self, panel: str) -> None:
        # Make sure viewFit frames the model panel, not your UI
        try:
            cmds.setFocus(panel)
        except RuntimeError:
            pass
        try:
            cmds.viewFit()
        except RuntimeError:
            # Last-resort fallback
            try:
                mel.eval("viewFit;")
            except RuntimeError:
                pass


    def _isolate_root(self, root: str, allow_toggle: bool) -> None:
        panel = self._find_model_panel()
        if not panel:
            _log("No active model panel found for isolate.")
            return

        is_isolated = cmds.isolateSelect(panel, q=True, state=True)

        # Toggle off if re-clicking the same RVA
        if is_isolated and allow_toggle and self._isolated_root == root:
            cmds.isolateSelect(panel, state=False)
            self._isolated_root = None
            _log("Isolation disabled for current panel.")
            return

        # Ensure the model panel has focus before manipulating isolate selection.
        try:
            cmds.setFocus(panel)
        except RuntimeError:
            pass

        # Reset isolate to avoid stale isolate sets when switching roots.
        if is_isolated and self._isolated_root != root:
            cmds.isolateSelect(panel, state=False)

        # Turn isolate on and replace the isolate set with the new hierarchy.
        cmds.isolateSelect(panel, state=True)
        cmds.select(root, hi=True, r=True)
        cmds.isolateSelect(panel, addSelected=True)

        self._isolated_root = root

        # Reframe in the right panel
        self._frame_in_panel(panel)
        _log("Isolated and framed RVA.")


    def _isolate_selected(self) -> None:
        root = self._current_root()
        if not root:
            return
        self._isolate_root(root, allow_toggle=True)


    def _isolate_relative(self, offset: int) -> None:
        total = self.rva_table.rowCount()
        if total == 0:
            return

        current_row = self.rva_table.currentRow()
        if current_row < 0:
            current_row = 0

        new_row = (current_row + offset) % total
        self.rva_table.setCurrentCell(new_row, 0)

        root_item = self.rva_table.item(new_row, 0)
        if not root_item:
            return

        root = root_item.data(QtCore.Qt.UserRole)
        if not root:
            return

        cmds.select(root, r=True)
        self._update_results_text(self.validation_results.get(root))
        self._isolate_root(root, allow_toggle=False)

    def _update_results_summary(self, results: dict[str, dict]) -> None:
        failed = [root for root, result in results.items() if not result.get("pass")]
        if not failed:
            self.results_box.setPlainText("All RVAs passed validation.")
            return
        lines = ["Validation failed for {} RVA(s):".format(len(failed))]
        for root in failed:
            result = results[root]
            issues = ", ".join(issue["message"] for issue in result.get("issues", []))
            lines.append("- {}: {}".format(_leaf_name(root), issues))
        self.results_box.setPlainText("\n".join(lines))

    def _toggle_uv_checker(self) -> None:
        panel = self._find_model_panel()
        if panel:
            try:
                cmds.modelEditor(panel, e=True, displayTextures=True)
            except RuntimeError:
                pass

        root = self._current_root()
        if not root:
            return
        meshes = _iter_mesh_shapes(root)
        if not meshes:
            _log("No meshes found for UV checker.")
            return
        enabled = self._uv_checker_enabled(meshes)
        shader_name = "rvaCheckerShader"
        sg_name = "rvaCheckerSG"
        if not enabled:
            if not cmds.objExists(shader_name):
                shader = cmds.shadingNode("lambert", asShader=True, name=shader_name)
                checker = cmds.shadingNode("checker", asTexture=True, name="rvaCheckerTex")
                place2d = cmds.shadingNode("place2dTexture", asUtility=True, name="rvaCheckerPlace2d")
                cmds.connectAttr("{}.outColor".format(checker), "{}.color".format(shader), force=True)
                cmds.connectAttr("{}.outUV".format(place2d), "{}.uvCoord".format(checker), force=True)
                cmds.connectAttr(
                    "{}.outUvFilterSize".format(place2d),
                    "{}.uvFilterSize".format(checker),
                    force=True,
                )
            else:
                shader = shader_name
            if not cmds.objExists(sg_name):
                sg = cmds.sets(renderable=True, noSurfaceShader=True, empty=True, name=sg_name)
                cmds.connectAttr("{}.outColor".format(shader), "{}.surfaceShader".format(sg), force=True)
            else:
                sg = sg_name
            self.checker_assignments = {}
            for mesh in meshes:
                shading_engines = cmds.listConnections(mesh, type="shadingEngine") or []
                self.checker_assignments[mesh] = (
                    shading_engines[0] if shading_engines else "initialShadingGroup"
                )
                cmds.sets(mesh, e=True, forceElement=sg)
            _safe_option_var_set(OPTIONVAR_UV_CHECKER, 1)
        else:
            if not self.checker_assignments:
                _log("No saved shading assignments to restore; resetting to default material.")
                for mesh in meshes:
                    cmds.sets(mesh, e=True, forceElement="initialShadingGroup")
            else:
                for mesh, sg in self.checker_assignments.items():
                    if sg:
                        cmds.sets(mesh, e=True, forceElement=sg)
            self.checker_assignments = {}
            _safe_option_var_set(OPTIONVAR_UV_CHECKER, 0)
        self._sync_uv_checker_state()

    def _show_uv_overlap(self) -> None:
        root = self._current_root()
        if not root:
            return
        meshes = _iter_mesh_shapes(root)
        if not meshes:
            _log("No meshes found for UV overlap check.")
            return
        if hasattr(cmds, "polyUVOverlap"):
            offenders = []
            for mesh in meshes:
                try:
                    result = cmds.polyUVOverlap(mesh)
                    if result:
                        offenders.append(mesh)
                except RuntimeError:
                    offenders.append(mesh)
            if offenders:
                cmds.select(offenders, r=True)
                _log("UV overlap detected on: {}".format(", ".join(offenders)))
            else:
                _log("No UV overlap detected.")
        else:
            _log("UV overlap check not available in this Maya version.")

    def _run_geo_checks(self) -> None:
        root = self._current_root()
        if not root:
            return
        meshes = _iter_mesh_shapes(root)
        nonmanifold = []
        lamina = []
        for mesh in meshes:
            if cmds.polyInfo(mesh, nonManifoldVertices=True):
                nonmanifold.append(mesh)
            if cmds.polyInfo(mesh, laminaFaces=True):
                lamina.append(mesh)
        if nonmanifold:
            _log("Nonmanifold geometry on: {}".format(", ".join(nonmanifold)))
        if lamina:
            _log("Lamina faces on: {}".format(", ".join(lamina)))
        if not nonmanifold and not lamina:
            _log("No nonmanifold or lamina issues detected.")

    def _uv_components(self, mesh_shape: str) -> list[str]:
        """Return expanded UV components for a mesh shape, or empty list."""
        uv_comp = cmds.polyListComponentConversion(mesh_shape, toUV=True) or []
        uv_comp = cmds.filterExpand(uv_comp, sm=35) or []
        return uv_comp

    def _selected_meshes(self, log_context: str) -> list[str]:
        selection = cmds.ls(sl=True, long=True) or []
        if not selection:
            _log("No selection for {}.".format(log_context))
            return []

        meshes = []
        for node in selection:
            base = node.split(".")[0]  # strips components like .f[0:5]
            if not cmds.objExists(base):
                continue

            node_type = cmds.nodeType(base)

            if node_type == "mesh":
                meshes.append(base)
            elif node_type == "transform":
                meshes.extend(
                    cmds.listRelatives(base, allDescendents=True, type="mesh", fullPath=True) or []
                )

        # Normalize + dedupe
        meshes = cmds.ls(meshes, long=True, type="mesh") or []
        meshes = list(dict.fromkeys(meshes))

        if not meshes:
            _log("No meshes found for {}.".format(log_context))
        return meshes

    def _run_uv_auto_mapping(self) -> None:
        meshes = self._selected_meshes("UV auto mapping")
        if not meshes:
            return

        failures = []
        _log("Has cmds.polyUnfold? {}".format(hasattr(cmds, "polyUnfold")))
        _log("Has cmds.polyUnfold3? {}".format(hasattr(cmds, "polyUnfold3")))

        for mesh in meshes:
            try:
                # Always get UV comps from Maya, not ".map[:]"
                uvs = self._uv_components(mesh)
                if not uvs:
                    raise RuntimeError("Mesh has no UV components to operate on.")

                # Auto projection
                cmds.polyAutoProjection(mesh, lm=0, pb=0, ibd=1, cm=0, l=2, sc=1, o=1, ps=0.2)

                # Select UVs for unfold/layout tools that depend on selection
                cmds.select(uvs, r=True)

                # --- Unfold (compatible across Maya versions) ---
                unfold_ran = False

                # Python cmds (newer Mayas)
                if hasattr(cmds, "polyUnfold"):
                    try:
                        cmds.polyUnfold(mesh, iterations=1, packing=0)
                        unfold_ran = True
                    except TypeError:
                        pass
                elif hasattr(cmds, "polyUnfold3"):
                    try:
                        cmds.polyUnfold3(mesh, iterations=1, packing=0)
                        unfold_ran = True
                    except TypeError:
                        pass

                # MEL fallbacks (older Mayas) - run on selected UVs
                if not unfold_ran:
                    try:
                        mel.eval("unfold;")
                        unfold_ran = True
                    except RuntimeError:
                        pass

                if not unfold_ran:
                    try:
                        mel.eval("performUnfold;")
                        unfold_ran = True
                    except RuntimeError:
                        pass

                if not unfold_ran:
                    raise RuntimeError("No available unfold method in this Maya version.")
                # --- end unfold ---

                # Refresh UV selection (some ops mess with it)
                uvs = self._uv_components(mesh)
                if not uvs:
                    raise RuntimeError("Mesh lost UV components after unfold.")
                cmds.select(uvs, r=True)

                # Orient / basic layout (selection-based)
                cmds.polyLayoutUV(rotateForBestFit=2, layout=0)

            except (RuntimeError, ValueError, TypeError) as e:
                failures.append(mesh)
                _log("UV auto mapping failed on {}: {}".format(mesh, e))

        if failures:
            _log("UV auto mapping failed on {} mesh(es).".format(len(failures)))

    def _run_uv_scaling(self) -> None:
        meshes = self._selected_meshes("UV scaling")
        if not meshes:
            return

        failures = []

        for mesh in meshes:
            try:
                uvs = self._uv_components(mesh)
                if not uvs:
                    raise RuntimeError("Mesh has no UV components to operate on.")

                # --- Density scaling using AREA (true 10cm tile density) ---
                # 0-1 UV tile = 10cm x 10cm => 1 UV area unit = 100 cm^2
                unit = cmds.currentUnit(q=True, linear=True)
                to_cm = {
                    "mm": 0.1,
                    "cm": 1.0,
                    "m": 100.0,
                    "in": 2.54,
                    "ft": 30.48,
                    "yd": 91.44,
                }.get(unit, 1.0)

                # World area in current linear units^2 -> convert to cm^2
                world_area = cmds.polyEvaluate(mesh, area=True)  # area in scene units^2
                world_area_cm2 = world_area * (to_cm**2)

                # UV area (this exists in most Mayas; if it errors we'll MEL fallback)
                try:
                    uv_area = cmds.polyEvaluate(mesh, uvArea=True)
                except TypeError:
                    # Older Maya: MEL fallback
                    uv_area = mel.eval('polyEvaluate -uvArea "{}";'.format(mesh))

                if not uv_area or uv_area <= 0.0:
                    raise RuntimeError("Mesh has zero UV area (can't scale density).")

                target_uv_area = world_area_cm2 / 100.0  # because 1 UV area == 100 cm^2
                scale = (target_uv_area / uv_area) ** 0.5

                # Scale ALL UVs for this mesh (explicit component string is fine for polyEditUV)
                uv_comp_str = "{}.map[:]".format(mesh)
                uv_bounds = cmds.polyEvaluate(mesh, boundingBox2d=True)
                uv_min, uv_max = uv_bounds
                pivot_u = (uv_min[0] + uv_max[0]) * 0.5
                pivot_v = (uv_min[1] + uv_max[1]) * 0.5

                _log("world_area_cm2={} uv_area={} scale={}".format(world_area_cm2, uv_area, scale))
                cmds.polyEditUV(
                    uv_comp_str,
                    scaleU=scale,
                    scaleV=scale,
                    pivotU=pivot_u,
                    pivotV=pivot_v,
                )

            except (RuntimeError, ValueError, TypeError) as e:
                failures.append(mesh)
                _log("UV scaling failed on {}: {}".format(mesh, e))

        if failures:
            _log("UV scaling failed on {} mesh(es).".format(len(failures)))

    def _run_uv_stacking(self) -> None:
        meshes = self._selected_meshes("UV stacking")
        if not meshes:
            return

        all_uvs_for_final_stack = []
        for mesh in meshes:
            uvs = self._uv_components(mesh)
            if uvs:
                all_uvs_for_final_stack.extend(uvs)

        if not all_uvs_for_final_stack:
            _log("No UVs found for UV stacking.")
            return

        # --- Final stack-only pass across ALL meshes (no packing) ---
        all_uvs_for_final_stack = list(dict.fromkeys(all_uvs_for_final_stack))
        cmds.select(all_uvs_for_final_stack, r=True)

        # Stack similar shells WITHOUT packing (packing can rescale to 0-1)
        try:
            cmds.polyLayoutUV(
                layout=0,  # IMPORTANT: no pack
                rotateForBestFit=0,  # keep your rotations if you want
                separate=0,
                stackSimilar=1,
                stackSimilarThreshold=0.08,
            )
        except TypeError:
            # If this Maya doesn't support stack flags, we can't auto-stack here
            _log("This Maya build doesn't support stackSimilar flags; skipping UV stacking.")





def _delete_existing_ui() -> None:
    """Delete existing window/workspace control."""
    if cmds.workspaceControl(WORKSPACE_CONTROL, exists=True):
        cmds.deleteUI(WORKSPACE_CONTROL)
    if cmds.window(WINDOW_NAME, exists=True):
        cmds.deleteUI(WINDOW_NAME)


def _dock_widget(widget: QtWidgets.QWidget) -> None:
    """Dock the widget inside a workspace control."""
    control = cmds.workspaceControl(WORKSPACE_CONTROL, label=WINDOW_TITLE, retain=False)
    ptr = omui.MQtUtil.findControl(control)
    if ptr is None:
        return
    qt_control = wrapInstance(int(ptr), QtWidgets.QWidget)
    layout = qt_control.layout() or QtWidgets.QVBoxLayout(qt_control)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(widget)


def _show_window(widget: QtWidgets.QWidget) -> None:
    """Show widget in a standalone window."""
    window = QtWidgets.QMainWindow()
    window.setObjectName(WINDOW_NAME)
    window.setWindowTitle(WINDOW_TITLE)
    window.setCentralWidget(widget)
    window.resize(900, 600)
    window.show()


def main() -> None:
    """Launch the RVA Tools UI."""
    _delete_existing_ui()
    widget = RVAToolsUI()
    try:
        _dock_widget(widget)
    except RuntimeError:
        _show_window(widget)


if __name__ == "__main__":
    main()
