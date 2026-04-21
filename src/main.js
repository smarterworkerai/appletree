import './style.css';
import * as THREE from 'three';

const canvas = document.querySelector('#scene');

const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
renderer.shadowMap.enabled = true;
renderer.outputColorSpace = THREE.SRGBColorSpace;

const scene = new THREE.Scene();
scene.background = new THREE.Color('#e8f4ff');
scene.fog = new THREE.Fog('#e8f4ff', 16, 38);

const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 100);
camera.position.set(7, 5, 9);
camera.lookAt(0, 2.5, 0);

const ambientLight = new THREE.HemisphereLight('#fff7e6', '#5f7c59', 1.8);
scene.add(ambientLight);

const sunLight = new THREE.DirectionalLight('#fff2d6', 2.2);
sunLight.position.set(6, 12, 5);
sunLight.castShadow = true;
sunLight.shadow.mapSize.set(2048, 2048);
sunLight.shadow.camera.left = -12;
sunLight.shadow.camera.right = 12;
sunLight.shadow.camera.top = 12;
sunLight.shadow.camera.bottom = -12;
scene.add(sunLight);

const ground = new THREE.Mesh(
  new THREE.CircleGeometry(18, 64),
  new THREE.MeshStandardMaterial({ color: '#7eb46a', roughness: 1 })
);
ground.rotation.x = -Math.PI / 2;
ground.receiveShadow = true;
scene.add(ground);

const trunkMaterial = new THREE.MeshStandardMaterial({
  color: '#7a4d2b',
  roughness: 1
});

const leavesMaterial = new THREE.MeshStandardMaterial({
  color: '#4d8f3a',
  roughness: 0.95
});

const appleMaterial = new THREE.MeshStandardMaterial({
  color: '#c62828',
  roughness: 0.7,
  metalness: 0.05
});

const tree = new THREE.Group();

const trunk = new THREE.Mesh(
  new THREE.CylinderGeometry(0.5, 0.85, 5.4, 12),
  trunkMaterial
);
trunk.position.y = 2.7;
trunk.castShadow = true;
tree.add(trunk);

function createBranch(length, radius, rotationZ, rotationY, position) {
  const branch = new THREE.Mesh(
    new THREE.CylinderGeometry(radius * 0.7, radius, length, 10),
    trunkMaterial
  );
  branch.position.copy(position);
  branch.rotation.z = rotationZ;
  branch.rotation.y = rotationY;
  branch.castShadow = true;
  return branch;
}

[
  createBranch(2.8, 0.22, -1.0, 0.2, new THREE.Vector3(-0.9, 4.4, 0.4)),
  createBranch(2.6, 0.2, 0.95, -0.4, new THREE.Vector3(0.95, 4.2, -0.1)),
  createBranch(2.1, 0.17, -0.45, 1.1, new THREE.Vector3(-0.25, 4.95, -0.85)),
  createBranch(1.9, 0.15, 0.55, -1.15, new THREE.Vector3(0.15, 5.1, 0.95))
].forEach((branch) => tree.add(branch));

function addLeafCluster(position, scale) {
  const cluster = new THREE.Mesh(
    new THREE.SphereGeometry(scale, 20, 20),
    leavesMaterial
  );
  cluster.position.copy(position);
  cluster.userData.basePosition = position.clone();
  cluster.castShadow = true;
  tree.add(cluster);
}

[
  [0, 6.2, 0, 2.2],
  [-1.9, 5.7, 0.3, 1.7],
  [1.8, 5.5, -0.1, 1.8],
  [-0.4, 5.3, -1.7, 1.5],
  [0.9, 5.7, 1.6, 1.4],
  [-1.1, 6.4, -1.0, 1.3],
  [1.2, 6.5, 0.8, 1.3]
].forEach(([x, y, z, scale]) => addLeafCluster(new THREE.Vector3(x, y, z), scale));

function addApple(position, scale = 0.18) {
  const apple = new THREE.Mesh(
    new THREE.SphereGeometry(scale, 16, 16),
    appleMaterial
  );
  apple.position.copy(position);
  apple.castShadow = true;
  tree.add(apple);

  const stem = new THREE.Mesh(
    new THREE.CylinderGeometry(0.015, 0.015, 0.16, 8),
    trunkMaterial
  );
  stem.position.copy(position).add(new THREE.Vector3(0, scale + 0.07, 0));
  stem.castShadow = true;
  tree.add(stem);
}

[
  [-0.2, 4.9, 1.6],
  [1.4, 5.2, 0.5],
  [-1.5, 5.1, -0.2],
  [0.7, 6.1, -1.0],
  [-0.9, 6.0, -1.3],
  [1.0, 5.7, 1.4],
  [-1.2, 5.5, 1.0],
  [0.1, 6.4, 0.3]
].forEach(([x, y, z]) => addApple(new THREE.Vector3(x, y, z)));

scene.add(tree);

const fallenApples = new THREE.Group();
[
  [-1.6, 0.2, 2.0],
  [1.9, 0.2, 1.3],
  [0.7, 0.2, -2.1]
].forEach(([x, y, z], index) => {
  const apple = new THREE.Mesh(
    new THREE.SphereGeometry(0.22, 16, 16),
    appleMaterial
  );
  apple.position.set(x, y, z);
  apple.rotation.z = index * 0.4;
  apple.castShadow = true;
  fallenApples.add(apple);
});
scene.add(fallenApples);

const breeze = { value: 0 };

function resize() {
  const { clientWidth, clientHeight } = canvas;
  const width = clientWidth || window.innerWidth;
  const height = clientHeight || window.innerHeight;

  renderer.setSize(width, height, false);
  camera.aspect = width / height;
  camera.updateProjectionMatrix();
}

window.addEventListener('resize', resize);
resize();

const clock = new THREE.Clock();

function render() {
  const elapsed = clock.getElapsedTime();
  breeze.value = Math.sin(elapsed * 0.8) * 0.04;
  tree.rotation.y = breeze.value;
  tree.children.forEach((child, index) => {
    if (child.geometry?.type === 'SphereGeometry' && child.material === leavesMaterial) {
      child.position.x = child.userData.basePosition.x + Math.sin(elapsed + index) * 0.04;
      child.position.z = child.userData.basePosition.z + Math.cos(elapsed * 0.9 + index) * 0.04;
    }
  });

  fallenApples.rotation.y = Math.sin(elapsed * 0.3) * 0.08;
  renderer.render(scene, camera);
}

renderer.setAnimationLoop(render);
