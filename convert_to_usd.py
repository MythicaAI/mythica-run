from pyassimp import load
from pxr import Usd, UsdGeom

def convert_to_usd(input_path, usd_output_path):
    """Convert a FBX scene into a USD stage"""
    with load(input_path) as scene:
        assert len(scene.meshes) > 0

        # Create USD stage
        stage = Usd.Stage.CreateNew(usd_output_path)
        root_layer = stage.GetRootLayer()

        # Iterate over the FBX scene and write to USD
        root_prim = UsdGeom.Xform.Define(stage, '/Root')

        # Add all the meshes to the stage
        for mesh in scene.meshes:
            # Create a USD Mesh prim for each FBX mesh
            mesh_prim_path = f"/Root/{mesh.name}"
            usd_mesh = UsdGeom.Mesh.Define(stage, mesh_prim_path)

            # Set vertices
            usd_mesh.CreatePointsAttr(mesh.vertices)

            # Set faces (indices)
            usd_mesh.CreateFaceVertexIndicesAttr(mesh.indices)

            # Optionally add transformations
            if mesh.translation:
                translation = mesh.translation
                usd_mesh.AddTranslateOp().Set((translation[0], translation[1], translation[2]))

    # Save USD file
    stage.GetRootLayer().Save()
    log.info(f"converted {input_path} to USD: {usd_output_path}")
