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


class RVAToolsUI(QtWidgets.QWidget):
    """Main UI for the RVA tool."""

    def __init__(self):
        super().__init__()
        self.setObjectName("rvaToolsWidget")
        self.validation_results: dict[str, dict] = {}
        self.last_export_paths: dict[str, str] = {}
        self.checker_assignments: dict[str, str] = {}
        self._isolated_root: str | None = None
        self._build_ui()
        self.refresh_list()

    def _build_ui(self) -> None:
        self.setLayout(QtWidgets.QVBoxLayout())

        self.rva_table = QtWidgets.QTableWidget(0, 5)
        self.rva_table.setHorizontalHeaderLabels(
            ["Root Name", "rvaCode", "Status", "Last Export", "Notes"]
        )
        self.rva_table.horizontalHeader().setStretchLastSection(True)
        self.rva_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.rva_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.rva_table.itemSelectionChanged.connect(self._on_row_selected)

        tag_layout = QtWidgets.QHBoxLayout()
        tag_layout.addWidget(self._make_button("Tag Selected as RVA", self._tag_selected))
        tag_layout.addWidget(self._make_button("Untag Selected", self._untag_selected))
        tag_layout.addWidget(self._make_button("Select All RVAs", self._select_all))
        tag_layout.addWidget(self._make_button("Refresh List", self.refresh_list))

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
        export_layout.addWidget(self._make_button("Export Selected", self._export_selected))
        export_layout.addWidget(self._make_button("Export All", self._export_all))

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

        self.layout().addWidget(self.rva_table)
        self.layout().addLayout(tag_layout)
        self.layout().addLayout(validate_layout)
        self.layout().addLayout(export_layout)
        self.layout().addLayout(utility_layout)
        self.layout().addLayout(view_layout)
        self.layout().addWidget(self.results_box)

        self._sync_uv_checker_state()

    def _uv_checker_enabled(self, meshes: list[str] | None = None) -> bool:
        sg_name = "rvaCheckerSG"
        if not cmds.objExists(sg_name):
            return False
    
        members = cmds.sets(sg_name, query=True) or []
        if not members:
            return False

    # Normalize members to long paths where possible
    long_members = set(cmds.ls(members, long=True) or members)

    if meshes is None:
        return True

    long_meshes = set(cmds.ls(meshes, long=True) or meshes)
    return len(long_members.intersection(long_meshes)) > 0


    def _make_button(self, label: str, callback, tooltip: str | None = None) -> QtWidgets.QPushButton:
        button = QtWidgets.QPushButton(label)
        button.clicked.connect(callback)
        button.setToolTip(tooltip or label)
        return button

    def _sync_uv_checker_state(self) -> None:
        enabled = self._uv_checker_enabled()
        self.uv_checker_button.setText("UV Checker On" if enabled else "UV Checker Off")

    def _current_root(self) -> str | None:
        selected = self.rva_table.selectedItems()
        if not selected:
            return self._find_selected_rva()
        return selected[0].data(QtCore.Qt.UserRole)

    def _find_selected_rva(self) -> str | None:
        selection = cmds.ls(sl=True, long=True, type="transform") or []
        if not selection:
            return None
        for node in selection:
            if cmds.attributeQuery("rva", node=node, exists=True):
                try:
                    if cmds.getAttr("{}.rva".format(node)):
                        return node
                except ValueError:
                    pass
            parents = cmds.listRelatives(node, allParents=True, fullPath=True) or []
            for parent in parents:
                if cmds.attributeQuery("rva", node=parent, exists=True):
                    try:
                        if cmds.getAttr("{}.rva".format(parent)):
                            return parent
                    except ValueError:
                        pass
        return None

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
        rva_code = cmds.getAttr("{}.rvaCode".format(root)) if cmds.attributeQuery("rvaCode", node=root, exists=True) else 0
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

    def _select_all(self) -> None:
        select_all_rvas()

    def _on_row_selected(self) -> None:
        root = self._current_root()
        if not root:
            return
        cmds.select(root, r=True)
        self._update_results_text(self.validation_results.get(root))

    def _validate_selected(self) -> None:
        root = self._current_root()
        if not root:
            _log("No RVA selected to validate.")
            return
        rvas = list_rva_roots()
        result = validate_rva(root, rvas)
        self.validation_results[root] = result
        self._update_row_status(root, result)
        self._update_results_text(result)
        self._print_validation_log(result)

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


    # Ensure validation exists
    if root not in self.validation_results:
        rvas = list_rva_roots()
        result = validate_rva(root, rvas)
        self.validation_results[root] = result
        self._update_row_status(root, result)
        self._update_results_text(result)

    offenders = self.validation_results.get(root, {}).get("offenders", [])
    if not offenders:
        _log("No offenders to select.")
        return

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
        shapes = cmds.listRelatives(xform, allDescendents=True, type="mesh", fullPath=True) or []
        for s in shapes:
            add_mesh_and_parent(s)

    for node in offenders:
        if not node:
            continue

        # Handle component strings like pCube1.vtx[0]
        base = node.split(".")[0]

        if not cmds.objExists(base):
            continue

        # Mesh shape offender
        if cmds.nodeType(base) == "mesh" or cmds.objectType(base, isAType="shape"):
            add_mesh_and_parent(base)
            continue

        # Transform offender
        if cmds.nodeType(base) == "transform":
            add_transform_and_meshes(base)
            continue

        # Any other node type: just add it if selectable
        expanded.add(base)

    # Final safety: keep only existing DAG nodes
    final = [n for n in sorted(expanded) if cmds.objExists(n)]
    if not final:
        _log("No existing offender nodes to select.")
        return

    try:
        cmds.select(final, r=True)
        _log("Selected {} offender node(s).".format(len(final)))
    except RuntimeError as e:
        _log("Selection warning: {}".format(e))
        safe = [n for n in final if cmds.objExists(n)]
        if safe:
            cmds.select(safe, r=True)


    # Ensure we have validation
    if root not in self.validation_results:
        rvas = list_rva_roots()
        result = validate_rva(root, rvas)
        self.validation_results[root] = result
        self._update_row_status(root, result)
        self._update_results_text(result)

    offenders = self.validation_results.get(root, {}).get("offenders", [])
    if not offenders:
        _log("No offenders to select.")
        return

    expanded = []
    for node in offenders:
        if not cmds.objExists(node):
            continue

        expanded.append(node)

        # If it's a shape, also include its parent transform
        if cmds.objectType(node, isAType="shape"):
            parents = cmds.listRelatives(node, parent=True, fullPath=True) or []
            expanded.extend(parents)

    expanded = sorted(set(expanded))
    if not expanded:
        _log("Offenders list contained no existing nodes.")
        return

    try:
        cmds.select(expanded, r=True)
        _log(f"Selected {len(expanded)} offender node(s).")
    except RuntimeError as e:
        # As a fallback, select only the ones Maya accepts
        safe = [n for n in expanded if cmds.objExists(n)]
        cmds.select(safe, r=True)
        _log(f"Selection warning: {e}")


    def _choose_export_dir(self) -> None:
        directory = cmds.fileDialog2(dialogStyle=2, fileMode=3)
        if directory:
            export_dir = directory[0]
            self.export_dir_field.setText(export_dir)
            _safe_option_var_set(OPTIONVAR_EXPORT_DIR, export_dir)

    def _export_selected(self) -> None:
        root = self._current_root()
        if not root:
            _log("No RVA selected to export.")
            return
        self._export_roots([root])

    def _export_all(self) -> None:
        rvas = list_rva_roots()
        if not rvas:
            _log("No RVAs to export.")
            return
        self._export_roots(rvas)

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

    def _delete_non_deformer_history(self) -> None:
        root = self._current_root()
        if not root:
            return
        cmds.bakePartialHistory(root, prePostDeformers=True)
        _log("Deleted non-deformer history for {}".format(_leaf_name(root)))

    def _freeze_transforms(self) -> None:
        root = self._current_root()
        if not root:
            return
        targets = _iter_mesh_transforms(root)
        targets.append(root)
        cmds.makeIdentity(targets, apply=True, t=1, r=1, s=1, n=0, pn=1)
        _log("Froze transforms for {}".format(_leaf_name(root)))

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

    # Turn isolate on
    cmds.isolateSelect(panel, state=True)

    # Select hierarchy, then REPLACE isolate set (this is the key)
    cmds.select(root, hi=True, r=True)
    cmds.isolateSelect(panel, loadSelected=True)

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
                cmds.connectAttr("{}.outUvFilterSize".format(place2d), "{}.uvFilterSize".format(checker), force=True)
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
                self.checker_assignments[mesh] = shading_engines[0] if shading_engines else ""
                cmds.sets(mesh, e=True, forceElement=sg)
            _safe_option_var_set(OPTIONVAR_UV_CHECKER, 1)
        else:
            if not self.checker_assignments:
                _log("No saved shading assignments to restore.")
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
