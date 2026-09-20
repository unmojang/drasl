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
  // Empty selects skinview3d's model detection.
  model: "classic" | "slim" | "";
  labels: SkinViewerLabels;
}

const DEG = Math.PI / 180;

// The idle pose is 90° into a 1.5-second cycle.
function poseAt(player: PlayerObject, time: number) {
  const angle = Math.sin(time * DEG);
  const capeAngle = Math.sin((time / 4) * DEG);
  player.skin.rightArm.rotation.x = -18 * DEG * angle;
  player.skin.leftArm.rotation.x = 18 * DEG * angle;
  player.skin.rightLeg.rotation.x = 20 * DEG * angle;
  player.skin.leftLeg.rotation.x = -20 * DEG * angle;
  player.cape.rotation.x = 18 * DEG - 6 * DEG * capeAngle;
}

export function showCSSSkin() {
  for (const el of document.querySelectorAll(
    ".css-skin-scene, .css-skin-controls",
  )) {
    el.classList.add("css-skin-shown");
  }
}

type SetLabel = (icon: string, description: string) => void;

function skinViewer(options: SkinViewerOptions) {
  const { canvas, labels } = options;

  let viewer;
  try {
    viewer = new SkinViewer({
      canvas: canvas,
      width: 280,
      height: canvas.parentElement!.clientHeight,
      // These values place the camera 60 units away.
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
  // Assigning the animation resets the joints.
  poseAt(viewer.playerObject, 90);

  // Rotate the camera so pointer controls remain relative to the model.
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
    icon: string,
    title: string,
    onClick: (setLabel: SetLabel) => void,
  ) => {
    const button = document.createElement("button");
    button.type = "button";
    const glyph = document.createElement("span");
    button.appendChild(glyph);
    const setLabel: SetLabel = (icon, description) => {
      glyph.className = "skin-icon " + icon;
      button.title = description;
      button.setAttribute("aria-label", description);
    };
    setLabel(icon, title);
    button.addEventListener("click", () => onClick(setLabel));
    controls.appendChild(button);
  };

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
  skinReady.catch(() => {
    viewer.dispose();
    canvas.hidden = true;
    controls.remove();
    showCSSSkin();
  });

  makeButton("skin-icon-play", labels.play, (setLabel) => {
    animation.paused = !animation.paused;
    setLabel(
      animation.paused ? "skin-icon-play" : "skin-icon-pause",
      animation.paused ? labels.play : labels.pause,
    );
  });

  if (capeReady) {
    skinReady
      .then(() => capeReady)
      .then(() => {
        let showElytra = false;
        makeButton("skin-icon-elytra", labels.showElytra, (setLabel) => {
          showElytra = !showElytra;
          viewer.playerObject.backEquipment = showElytra ? "elytra" : "cape";
          setLabel(
            showElytra ? "skin-icon-cape" : "skin-icon-elytra",
            showElytra ? labels.showCape : labels.showElytra,
          );
        });
      })
      .catch(() => {});
  }
}

export default skinViewer;
