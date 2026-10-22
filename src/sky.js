export function createSunDisc(THREE) {
  const sun = new THREE.Group();
  sun.name = 'sun-disc';
  sun.position.set(3.5, 2.2, -8);
  sun.renderOrder = -1;

  const halo = new THREE.Mesh(
    new THREE.CircleGeometry(1.05, 64),
    new THREE.MeshBasicMaterial({
      color: '#ffe8a3',
      transparent: true,
      opacity: 0.32,
      depthTest: false,
      depthWrite: false
    })
  );

  const disc = new THREE.Mesh(
    new THREE.CircleGeometry(0.72, 64),
    new THREE.MeshBasicMaterial({
      color: '#ffd166',
      depthTest: false,
      depthWrite: false
    })
  );
  disc.position.z = 0.01;

  sun.add(halo, disc);
  return sun;
}

export function positionSunDisc(sun, camera, distance = 8) {
  const visibleHeight = 2 * Math.tan((camera.fov * Math.PI / 180) / 2) * distance;
  const halfWidth = visibleHeight * camera.aspect / 2;
  sun.position.set(halfWidth - 1.15, visibleHeight / 2 - 1.05, -distance);
}
