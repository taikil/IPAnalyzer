# Raytracer Readme

#Completed Tasks

```
testAmbient - Complete
testBackground - Complete
testBehind - Complete
testDiffuse - Complete
testIllum - Complete
testImgPlane - Complete
testIntersectons - Complete
testParsing - Complete
testReflection - Complete
testSample - Complete
testShadow - Complete
testSpecular - Complete

```This raytracer program simulates the rendering of 3D scenes using the ray tracing technique. To compile and run the raytracer, follow the instructions below.## CompilationTo compile the raytracer, navigate to the project directory and use the provided `Makefile`. Open a terminal and run:```bashmake```This will compile the source code and generate the executable `Raytracer`.## ExecutionAfter successfully compiling, run the raytracer by executing the following command:```bash./Raytracer [input_file]```Replace `[input_file]` with the path to your scene description file. The input file should follow the specified format detailed below.## Input File FormatThe input file specifies the parameters of the scene, including camera settings, sphere properties, light positions, and background colors. The format should adhere to the following structure:```plaintextNEAR <n>LEFT <l>RIGHT <r>BOTTOM <b>TOP <t>SPHERE <name> <pos x> <pos y> <pos z> <scl x> <scl y> <scl z> <r> <g> <b> <ka> <kd> <ks> <kr> <n># Additional SPHERE specifications (up to 14)LIGHT <name> <pos x> <pos y> <pos z> <ir> <ig> <ib># Additional LIGHT specifications (up to 9)BACK <r> <g> <b>AMBIENT <ir> <ig> <ib>OUTPUT <name>```- `NEAR`, `LEFT`, `RIGHT`, `BOTTOM`, `TOP`: Camera parameters.- `SPHERE`: Sphere specifications including position, scale, color, material properties (ambient, diffuse, specular, reflection), and shininess.- `LIGHT`: Light specifications including position and color.- `BACK`: Background color.- `AMBIENT`: Ambient light color.- `OUTPUT`: Output filename.