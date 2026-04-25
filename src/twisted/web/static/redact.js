// Browser-side PII redaction tool for screenshots.
// No build step, no framework — vanilla JS + canvas. ~120 lines.
//
// Flow:
//   1) Operator picks a screenshot via <input type="file">
//   2) Image renders into <canvas>, dimensions captured
//   3) Operator drags rectangles on top of the canvas; each one is
//      stored in `rectangles` and drawn as a solid black overlay
//   4) Submit posts FormData containing the original file + the JSON
//      rectangles array (in image-pixel coords) to the server, which
//      uses Pillow to bake them in and saves the redacted PNG
//      alongside the original as evidence on the chosen finding.
//
// All coordinates are converted from canvas-display-space back to
// image-pixel-space so the server-side redactor produces a result
// that matches what the operator drew on screen.

(function () {
  const fileInput = document.getElementById("redact-file");
  const canvas = document.getElementById("redact-canvas");
  const ctx = canvas.getContext("2d");
  const undoBtn = document.getElementById("redact-undo");
  const clearBtn = document.getElementById("redact-clear");
  const form = document.getElementById("redact-form");
  const rectsField = document.getElementById("redact-rects");
  const dimsLabel = document.getElementById("redact-dims");

  if (!fileInput || !canvas || !form) {
    return;
  }

  let img = null;
  // Image's true pixel dimensions
  let imgWidth = 0;
  let imgHeight = 0;
  // Scale factor between displayed canvas and underlying image
  let scale = 1.0;
  // Rectangles in IMAGE-PIXEL coords: {x, y, width, height}
  let rectangles = [];
  let dragStart = null;

  fileInput.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const url = URL.createObjectURL(file);
    img = new Image();
    img.onload = () => {
      imgWidth = img.naturalWidth;
      imgHeight = img.naturalHeight;
      // Cap display width at 800px while preserving aspect.
      const maxDisplay = Math.min(800, imgWidth);
      scale = maxDisplay / imgWidth;
      canvas.width = Math.round(imgWidth * scale);
      canvas.height = Math.round(imgHeight * scale);
      rectangles = [];
      redraw();
      dimsLabel.textContent = `${imgWidth} × ${imgHeight} px`;
      URL.revokeObjectURL(url);
    };
    img.src = url;
  });

  function redraw() {
    if (!img) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "rgba(0, 0, 0, 1.0)";
    rectangles.forEach((r) => {
      ctx.fillRect(r.x * scale, r.y * scale, r.width * scale, r.height * scale);
    });
    if (dragStart && dragStart.live) {
      ctx.strokeStyle = "rgba(255, 0, 0, 0.9)";
      ctx.lineWidth = 1;
      const w = dragStart.curX - dragStart.startX;
      const h = dragStart.curY - dragStart.startY;
      ctx.strokeRect(dragStart.startX, dragStart.startY, w, h);
    }
  }

  function canvasCoords(evt) {
    const r = canvas.getBoundingClientRect();
    return { x: evt.clientX - r.left, y: evt.clientY - r.top };
  }

  canvas.addEventListener("mousedown", (e) => {
    if (!img) return;
    const p = canvasCoords(e);
    dragStart = { startX: p.x, startY: p.y, curX: p.x, curY: p.y, live: true };
  });

  canvas.addEventListener("mousemove", (e) => {
    if (!dragStart || !dragStart.live) return;
    const p = canvasCoords(e);
    dragStart.curX = p.x;
    dragStart.curY = p.y;
    redraw();
  });

  canvas.addEventListener("mouseup", (e) => {
    if (!dragStart) return;
    const p = canvasCoords(e);
    dragStart.curX = p.x;
    dragStart.curY = p.y;
    const x0 = Math.min(dragStart.startX, dragStart.curX);
    const y0 = Math.min(dragStart.startY, dragStart.curY);
    const w = Math.abs(dragStart.curX - dragStart.startX);
    const h = Math.abs(dragStart.curY - dragStart.startY);
    if (w > 3 && h > 3) {
      rectangles.push({
        x: Math.round(x0 / scale),
        y: Math.round(y0 / scale),
        width: Math.round(w / scale),
        height: Math.round(h / scale),
      });
    }
    dragStart = null;
    redraw();
  });

  undoBtn.addEventListener("click", () => {
    rectangles.pop();
    redraw();
  });

  clearBtn.addEventListener("click", () => {
    rectangles = [];
    redraw();
  });

  form.addEventListener("submit", () => {
    rectsField.value = JSON.stringify(rectangles);
  });
})();
