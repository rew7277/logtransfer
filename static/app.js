document.addEventListener("DOMContentLoaded", () => {
  const flashes = document.querySelectorAll(".flash");
  if (flashes.length) {
    setTimeout(() => flashes.forEach(el => el.style.opacity = "0"), 2800);
  }
});
