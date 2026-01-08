import csv
import maya.cmds as cmds


WINDOW_NAME = "primitiveCreatorUI"
CSV_ITEMS = []
CSV_FIELDNAMES = []


def _convert_to_cm(value, unit):
    if unit == "in":
        return value * 2.54
    return value


def _axis_rotation(up_axis):
    if up_axis == "X":
        return (0.0, 0.0, -90.0)
    if up_axis == "Z":
        return (90.0, 0.0, 0.0)
    return (0.0, 0.0, 0.0)


def _center_bottom(transform, up_axis):
    bbox = cmds.exactWorldBoundingBox(transform)
    min_x, min_y, min_z, max_x, max_y, max_z = bbox
    center_x = (min_x + max_x) * 0.5
    center_y = (min_y + max_y) * 0.5
    center_z = (min_z + max_z) * 0.5

    if up_axis == "X":
        offset = (-min_x, -center_y, -center_z)
    elif up_axis == "Z":
        offset = (-center_x, -center_y, -min_z)
    else:
        offset = (-center_x, -min_y, -center_z)

    cmds.move(offset[0], offset[1], offset[2], transform, relative=True)


def _update_depth_field(*_):
    shape = cmds.optionMenu("pc_shape", query=True, value=True)
    is_cube = shape == "Cube"
    cmds.floatField("pc_depth", edit=True, enable=is_cube)


def _build_primitive(shape, unit, up_axis, center_bottom, width, height, depth, name=None):
    if shape not in {"Plane", "Cube"}:
        shape = "Cube"
    if unit not in {"cm", "in"}:
        unit = "cm"
    if up_axis not in {"X", "Y", "Z"}:
        up_axis = "Y"

    width_cm = _convert_to_cm(width, unit)
    height_cm = _convert_to_cm(height, unit)
    depth_cm = _convert_to_cm(depth, unit)

    rotation = _axis_rotation(up_axis)

    if shape == "Plane":
        normal = {"X": (1, 0, 0), "Y": (0, 1, 0), "Z": (0, 0, 1)}[up_axis]
        transform, _ = cmds.polyPlane(w=width_cm, h=height_cm, ax=normal, name=name)
    else:
        transform, _ = cmds.polyCube(w=width_cm, h=height_cm, d=depth_cm, name=name)
        if rotation != (0.0, 0.0, 0.0):
            cmds.rotate(rotation[0], rotation[1], rotation[2], transform, absolute=True)

    if center_bottom:
        _center_bottom(transform, up_axis)
    return transform


def _create_primitive(*_):
    shape = cmds.optionMenu("pc_shape", query=True, value=True)
    unit = cmds.optionMenu("pc_unit", query=True, value=True)
    up_axis = cmds.optionMenu("pc_up_axis", query=True, value=True)
    center_bottom = cmds.optionMenu("pc_center_bottom", query=True, value=True) == "On"

    width = cmds.floatField("pc_width", query=True, value=True)
    height = cmds.floatField("pc_height", query=True, value=True)
    depth = cmds.floatField("pc_depth", query=True, value=True)

    _build_primitive(shape, unit, up_axis, center_bottom, width, height, depth)


def _parse_bool(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _create_from_csv(*_):
    selection = cmds.fileDialog2(fileMode=1, caption="Select CSV", fileFilter="CSV Files (*.csv)")
    if not selection:
        return

    csv_path = selection[0]
    rows = []
    items = []
    with open(csv_path, newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        if reader.fieldnames:
            header = " | ".join(reader.fieldnames)
            items.append(header)
            global CSV_FIELDNAMES
            CSV_FIELDNAMES = reader.fieldnames
        for row in reader:
            name = row.get("name") or None
            shape = (row.get("shape") or "Cube").strip().title()
            unit = (row.get("unit") or "cm").strip().lower()
            up_axis = (row.get("up_axis") or "Y").strip().upper()
            center_bottom = _parse_bool(row.get("center_bottom"))

            width = float(row.get("width", 0.0))
            height = float(row.get("height", 0.0))
            depth = float(row.get("depth", 0.0))

            if shape == "Plane":
                depth = 0.0

            rows.append(
                {
                    "name": name,
                    "shape": shape,
                    "unit": unit,
                    "up_axis": up_axis,
                    "center_bottom": center_bottom,
                    "width": width,
                    "height": height,
                    "depth": depth,
                    "csv_row": row,
                }
            )
            if reader.fieldnames:
                values = [str(row.get(field, "")) for field in reader.fieldnames]
                items.append(" | ".join(values))

    global CSV_ITEMS
    CSV_ITEMS = rows
    cmds.textScrollList("pc_csv_list", edit=True, removeAll=True)
    if items:
        cmds.textScrollList("pc_csv_list", edit=True, append=items)
    _update_name_column_menu()


def _update_name_column_menu():
    cmds.optionMenu("pc_name_column", edit=True, deleteAllItems=True)
    if not CSV_FIELDNAMES:
        cmds.menuItem(label="name")
        return
    for field in CSV_FIELDNAMES:
        cmds.menuItem(label=field)


def _create_from_loaded_csv(*_):
    name_column = cmds.optionMenu("pc_name_column", query=True, value=True)
    shape = cmds.optionMenu("pc_shape", query=True, value=True)
    unit = cmds.optionMenu("pc_unit", query=True, value=True)
    up_axis = cmds.optionMenu("pc_up_axis", query=True, value=True)
    center_bottom = cmds.optionMenu("pc_center_bottom", query=True, value=True) == "On"
    width = cmds.floatField("pc_width", query=True, value=True)
    height = cmds.floatField("pc_height", query=True, value=True)
    depth = cmds.floatField("pc_depth", query=True, value=True)
    for row in CSV_ITEMS:
        name = row["name"]
        csv_row = row.get("csv_row") or {}
        if name_column in csv_row:
            name_value = str(csv_row.get(name_column)).strip()
            if name_value:
                name = name_value
        group_name = name or "csv_object"
        group = cmds.group(empty=True, name=group_name)
        mesh_name = f"{group_name}_geo"
        transform = _build_primitive(
            shape,
            unit,
            up_axis,
            center_bottom,
            width,
            height,
            depth,
            name=mesh_name,
        )
        cmds.parent(transform, group)


def show():
    if cmds.window(WINDOW_NAME, exists=True):
        cmds.deleteUI(WINDOW_NAME)

    cmds.window(WINDOW_NAME, title="Create Plane or Cube", sizeable=True)
    cmds.columnLayout(adjustableColumn=True, rowSpacing=8)

    cmds.text(label="Select a primitive and set dimensions")

    cmds.rowLayout(numberOfColumns=2, adjustableColumn=2, columnAlign=(1, "right"))
    cmds.text(label="Shape")
    cmds.optionMenu("pc_shape", changeCommand=_update_depth_field)
    cmds.menuItem(label="Plane")
    cmds.menuItem(label="Cube")
    cmds.setParent("..")

    cmds.rowLayout(numberOfColumns=2, adjustableColumn=2, columnAlign=(1, "right"))
    cmds.text(label="Units")
    cmds.optionMenu("pc_unit")
    cmds.menuItem(label="cm")
    cmds.menuItem(label="in")
    cmds.setParent("..")

    cmds.rowLayout(numberOfColumns=2, adjustableColumn=2, columnAlign=(1, "right"))
    cmds.text(label="Up Axis")
    cmds.optionMenu("pc_up_axis")
    cmds.menuItem(label="X")
    cmds.menuItem(label="Y")
    cmds.menuItem(label="Z")
    cmds.setParent("..")

    cmds.rowLayout(numberOfColumns=2, adjustableColumn=2, columnAlign=(1, "right"))
    cmds.text(label="Center Bottom")
    cmds.optionMenu("pc_center_bottom")
    cmds.menuItem(label="Off")
    cmds.menuItem(label="On")
    cmds.setParent("..")

    cmds.rowLayout(numberOfColumns=2, adjustableColumn=2, columnAlign=(1, "right"))
    cmds.text(label="Width")
    cmds.floatField("pc_width", value=100.0, minValue=0.01)
    cmds.setParent("..")

    cmds.rowLayout(numberOfColumns=2, adjustableColumn=2, columnAlign=(1, "right"))
    cmds.text(label="Height")
    cmds.floatField("pc_height", value=100.0, minValue=0.01)
    cmds.setParent("..")

    cmds.rowLayout(numberOfColumns=2, adjustableColumn=2, columnAlign=(1, "right"))
    cmds.text(label="Depth")
    cmds.floatField("pc_depth", value=100.0, minValue=0.01)
    cmds.setParent("..")

    cmds.separator(height=8, style="in")
    cmds.button(label="Create", command=_create_primitive)
    cmds.separator(height=8, style="in")
    cmds.text(label="CSV Preview")
    cmds.textScrollList("pc_csv_list", numberOfRows=6)
    cmds.rowLayout(numberOfColumns=2, adjustableColumn=2, columnAlign=(1, "right"))
    cmds.text(label="Name Column")
    cmds.optionMenu("pc_name_column")
    cmds.menuItem(label="name")
    cmds.setParent("..")
    cmds.button(label="Load CSV", command=_create_from_csv)
    cmds.button(label="Create From CSV", command=_create_from_loaded_csv)

    _update_depth_field()
    cmds.showWindow(WINDOW_NAME)


show()
