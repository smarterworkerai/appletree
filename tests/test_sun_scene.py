"""The sun uses actual Three.js objects without a browser or WebGL context."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SunSceneTest(unittest.TestCase):
    def test_sun_disc_is_a_layered_camera_space_scene_feature(self):
        script = """
import * as THREE from 'three';
import { createSunDisc, positionSunDisc } from './src/sky.js';
const sun = createSunDisc(THREE);
if (sun.name !== 'sun-disc') throw new Error('sun-name');
if (sun.children.length !== 2) throw new Error('sun-layers');
if (sun.position.x <= 0 || sun.position.y <= 0 || sun.position.z >= 0) throw new Error('sun-position');
if (!sun.children.every(child => child.material.depthTest === false && child.material.depthWrite === false)) {
  throw new Error('sun-depth');
}
const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 100);
camera.add(sun);
positionSunDisc(sun, camera);
const square = sun.position.clone();
camera.aspect = 2;
positionSunDisc(sun, camera);
if (!(sun.position.x > square.x && sun.position.y === square.y && sun.position.z === square.z)) {
  throw new Error('sun-resize');
}
if (sun.parent !== camera) throw new Error('sun-camera-space');
"""
        subprocess.run(['node', '--input-type=module', '--eval', script],
                       cwd=ROOT, check=True, text=True, capture_output=True)


if __name__ == '__main__':
    unittest.main()
