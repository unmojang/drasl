import * as THREE from "three";
import { supported } from "@mapbox/mapbox-gl-supported";

import endPortalUrl from "./end-portal.png";

const vertShader = `
varying vec3 v_normal;
varying vec2 v_texcoord;

uniform float u_angle;
uniform sampler2D u_texture;

const float TIME_SCALE = 1.0 / 30.0;

mat4 rotateAxis(vec3 axis, float angle) {
	// From https://www.neilmendoza.com/glsl-rotation-about-an-arbitrary-axis/
	axis = normalize(axis);
	float s = sin(angle);
	float c = cos(angle);
	float oc = 1.0 - c;

	return mat4(oc * axis.x * axis.x + c,           oc * axis.x * axis.y - axis.z * s,  oc * axis.z * axis.x + axis.y * s,  0.0,
	            oc * axis.x * axis.y + axis.z * s,  oc * axis.y * axis.y + c,           oc * axis.y * axis.z - axis.x * s,  0.0,
	            oc * axis.z * axis.x - axis.y * s,  oc * axis.y * axis.z + axis.x * s,  oc * axis.z * axis.z + c,           0.0,
	            0.0,                                0.0,                                0.0,                                1.0);
}

void main() {
	// twist knot in on itself

	v_normal = mat3(normalMatrix) * normal;
	v_texcoord = uv;

	// average radius of the knot
	float r = 1.0;

	// assume knot is centered at 0, 0, 0
	vec3 closest_on_circle = r * normalize(vec3(position.xy, 0.0));

	vec3 offset = position - closest_on_circle;
	float angle = u_angle;

	vec3 axis = cross(vec3(0, 0, 1), closest_on_circle);

	vec3 new_position = closest_on_circle + (vec4(offset, 1.0) * rotateAxis(axis, angle)).xyz;

	gl_Position = projectionMatrix * modelViewMatrix * vec4(new_position, 1.0);
}
`;

const fragShader = `
varying vec3 v_normal;
varying vec2 v_texcoord;

uniform float u_time;
uniform sampler2D u_texture;

const float TIME_SCALE = 1.0 / 1500.0;

const mat4 SCALE_TRANSLATE = mat4(
	0.5, 0.0, 0.0, 0.25,
	0.0, 0.5, 0.0, 0.25,
	0.0, 0.0, 1.0, 0.0,
	0.0, 0.0, 0.0, 1.0
);

mat2 mat2_rotate_z(float radians) {
	return mat2(
		cos(radians), -sin(radians),
		sin(radians), cos(radians)
	);
}

mat4 end_portal_layer(float layer) {
	mat4 translate = mat4(
		1.0, 0.0, 0.0, 17.0 / layer,
		0.0, 1.0, 0.0, (2.0 + layer / 1.5) * (TIME_SCALE * u_time * -1.5),
		0.0, 0.0, 1.0, 0.0,
		0.0, 0.0, 0.0, 1.0
	);

	mat2 rotate = mat2_rotate_z(3.3 + radians((layer * layer * 4321.0 + layer * 9.0) * 2.0));

	mat2 scale = mat2((4.5 - layer / 4.0) * 2.0);

	return mat4(scale * rotate) * translate * SCALE_TRANSLATE;
}

const float s = 1.5;
const mat2 texcoord_scale = mat2(
	20.0 * s, 0.0,
	0.0, 1.0 * s
);

vec3 layer_contribution(float i, vec3 layer_color) {
	return textureProj(u_texture, vec4(v_texcoord * texcoord_scale, 0.0, 1.0) * end_portal_layer(i)).rgb * layer_color;
}

out vec4 fragColor;

void main() {
	vec3 color = 0.1 * vec3(0.0847636875, 0.166413125, 0.1975476875);
	color += layer_contribution(9.0,  vec3(0.106152, 0.131144, 0.195191));
	color += layer_contribution(10.0, vec3(0.097721, 0.110188, 0.187229));
	color += layer_contribution(11.0, vec3(0.133516, 0.138278, 0.148582));
	color += layer_contribution(12.0, vec3(0.070006, 0.243332, 0.235792));
	color += layer_contribution(13.0, vec3(0.196766, 0.142899, 0.214696));
	color += layer_contribution(14.0, vec3(0.047281, 0.315338, 0.321970));
	color += layer_contribution(15.0, vec3(0.204675, 0.390010, 0.302066));
	color += layer_contribution(16.0, vec3(0.080955, 0.314821, 0.661491));
	fragColor = vec4(color, 1.0);
}
`;

async function background(el: HTMLDivElement) {
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(
    30,
    window.innerWidth / window.innerHeight,
    0.1,
    1000,
  );
  camera.position.z = 3;

  const loader = new THREE.TextureLoader();

  const loadTexture = async function loadTexture(
    path: string,
  ): Promise<THREE.Texture> {
    return new Promise((resolve) => {
      loader.load(path, (data) => resolve(data));
    });
  };

  const [endPortalTexture] = await Promise.all([loadTexture(endPortalUrl)]);
  endPortalTexture.wrapS = THREE.RepeatWrapping;
  endPortalTexture.wrapT = THREE.RepeatWrapping;
  endPortalTexture.magFilter = THREE.NearestFilter;
  endPortalTexture.minFilter = THREE.NearestFilter;

  // TorusKnotGeometry(radius, tube radius, tubularSegments, radialSegments, p, q)
  const geometry = new THREE.TorusKnotGeometry(1.0, 0.18, 140, 20, 4, 3);

  const timeUniform = { value: 0 };
  const angleUniform = { value: 0 };
  const material = new THREE.ShaderMaterial({
    uniforms: {
      u_time: timeUniform,
      u_angle: angleUniform,
      u_texture: { value: endPortalTexture },
    },
    vertexShader: vertShader,
    fragmentShader: fragShader,
    glslVersion: THREE.GLSL3,
  });

  // Draw wireframe
  // const geo = new THREE.EdgesGeometry(geometry); // or WireframeGeometry( geometry )
  // const mat = new THREE.LineBasicMaterial( { color: 0xffffff, linewidth: 2 } );
  // const wireframe = new THREE.LineSegments( geo, mat );
  // scene.add( wireframe );

  const knot = new THREE.Mesh(geometry, material);
  scene.add(knot);

  const renderer = new THREE.WebGLRenderer();
  renderer.setSize(window.innerWidth, window.innerHeight);
  el.appendChild(renderer.domElement);

  const isSupported = supported({ failIfMajorPerformanceCaveat: true });
  let shouldAnimate = isSupported;

  const prmQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  const handleChangePrm = () => {
    shouldAnimate = isSupported && !prmQuery.matches;
    render();
  };
  handleChangePrm();
  prmQuery.addEventListener("change", handleChangePrm);

  function render() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);

    if (shouldAnimate) {
      const time = performance.now() / 1000;
      timeUniform.value = time;
      angleUniform.value =
        ((performance.timeOrigin + performance.now()) / 1000 / 30) %
        (2 * Math.PI);
    }

    renderer.render(scene, camera);

    if (shouldAnimate) {
      requestAnimationFrame(render);
    }
  }

  let dimensions = { width: window.innerWidth, height: window.innerHeight };
  const resizeObserver = new ResizeObserver((entries) => {
    for (const entry of entries) {
      const { width, height } = entry.contentRect;
      dimensions = { width: Math.round(width), height: Math.round(height) };
      render();
    }
  });
  resizeObserver.observe(el);
}

export default background;
