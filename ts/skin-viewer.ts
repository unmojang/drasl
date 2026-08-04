import { FunctionAnimation, PlayerObject, SkinViewer } from "skinview3d";

export interface SkinViewerLabels {
  play: string;
  pause: string;
  showElytra: string;
  showCape: string;
}

export interface SkinViewerOptions {
  canvas: HTMLCanvasElement;
  skinURL: string;
  capeURL?: string | null;
  // Empty when only a fallback API server could say, so read it off the texture
  model: "classic" | "slim" | "";
  labels: SkinViewerLabels;
}

const DEG = Math.PI / 180;

// Time in degrees, advancing 360° every 1.5s; 90 is the default frame.
function poseAt(player: PlayerObject, time: number) {
  const angle = Math.sin(time * DEG);
  const capeAngle = Math.sin((time / 4) * DEG);
  player.skin.rightArm.rotation.x = -18 * DEG * angle;
  player.skin.leftArm.rotation.x = 18 * DEG * angle;
  player.skin.rightLeg.rotation.x = 20 * DEG * angle;
  player.skin.leftLeg.rotation.x = -20 * DEG * angle;
  player.cape.rotation.x = 18 * DEG - 6 * DEG * capeAngle;
}

// With scripting on the <noscript> style never applies, so a failed start has
// to reveal the CSS model itself.
export function showCSSSkin() {
  for (const el of document.querySelectorAll(
    ".css-skin-scene, .css-skin-controls",
  )) {
    el.classList.add("css-skin-shown");
  }
}

interface ButtonFace {
  icon?: string;
  text?: string;
}

type SetLabel = (face: ButtonFace, description: string) => void;

function skinViewer(options: SkinViewerOptions) {
  const { canvas, labels } = options;

  let viewer;
  try {
    viewer = new SkinViewer({
      canvas: canvas,
      width: 200,
      height: canvas.parentElement!.clientHeight,
      // fov 38 at distance 60 (skinview3d derives distance = 4.5 + 16.5/tan(fov/2)/zoom).
      fov: 38,
      zoom: 0.863,
    });
  } catch (e) {
    showCSSSkin();
    throw e;
  }
  canvas.hidden = false;
  viewer.controls.enableZoom = false;

  const animation = new FunctionAnimation((player, progress) => {
    poseAt(player, 90 + progress * 240);
  });
  viewer.animation = animation;
  animation.paused = true;
  // After assigning the animation, whose setter resets the player's joints.
  poseAt(viewer.playerObject, 90);

  // Angle the camera (30° of yaw, 21° of pitch) rather than the model, so
  // drag-to-rotate stays natural.
  {
    const dist = viewer.camera.position.length();
    const az = -30 * DEG;
    const pol = (90 - 21) * DEG;
    viewer.camera.position.set(
      dist * Math.sin(pol) * Math.sin(az),
      dist * Math.cos(pol),
      dist * Math.sin(pol) * Math.cos(az),
    );
    viewer.controls.update();
  }

  const controls = document.createElement("div");
  controls.className = "skin-controls";
  canvas.parentElement!.appendChild(controls);

  const makeButton = (
    face: ButtonFace,
    title: string,
    onClick: (setLabel: SetLabel) => void,
  ) => {
    const button = document.createElement("button");
    button.type = "button";
    const glyph = document.createElement("span");
    button.appendChild(glyph);
    const setLabel: SetLabel = (face, description) => {
      glyph.className = face.icon ? "skin-icon " + face.icon : "";
      glyph.textContent = face.text ?? "";
      button.title = description;
      // The glyph would otherwise be the button's whole accessible name.
      button.setAttribute("aria-label", description);
    };
    setLabel(face, title);
    button.addEventListener("click", (e) => {
      onClick(setLabel);
      if (e.detail) button.blur(); // let the controls fade after a mouse click
    });
    controls.appendChild(button);
  };

  // Reveal only once every texture is ready, so neither pops in first.
  viewer.playerObject.visible = false;
  const skinReady = viewer.loadSkin(options.skinURL, {
    model:
      options.model === "slim"
        ? "slim"
        : options.model === "classic"
          ? "default"
          : "auto-detect",
  });
  const capeReady = options.capeURL ? viewer.loadCape(options.capeURL) : null;
  Promise.allSettled([skinReady, capeReady]).then(() => {
    viewer.playerObject.visible = true;
  });
  // A viewer without its skin renders nothing.
  skinReady.catch(() => {
    viewer.dispose();
    canvas.hidden = true;
    controls.remove();
    showCSSSkin();
  });

  makeButton({ icon: "skin-icon-play" }, labels.play, (setLabel) => {
    animation.paused = !animation.paused;
    setLabel(
      { icon: animation.paused ? "skin-icon-play" : "skin-icon-pause" },
      animation.paused ? labels.play : labels.pause,
    );
  });

  if (capeReady) {
    // Only after the cape loads: toggling would drape an untextured cape/elytra.
    skinReady
      .then(() => capeReady)
      .then(() => {
        let showElytra = false;
        makeButton({ text: "🪽" }, labels.showElytra, (setLabel) => {
          showElytra = !showElytra;
          viewer.playerObject.backEquipment = showElytra ? "elytra" : "cape";
          setLabel(
            { text: showElytra ? "🦸" : "🪽" },
            showElytra ? labels.showCape : labels.showElytra,
          );
        });
      })
      .catch(() => {});
  }
}

export default skinViewer;
