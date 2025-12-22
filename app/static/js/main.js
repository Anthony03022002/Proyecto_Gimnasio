(function () {
  const mesesEl = document.getElementById("meses");
  const desdeEl = document.getElementById("fecha_desde");
  const hastaEl = document.getElementById("fecha_hasta");

  if (!mesesEl || !desdeEl || !hastaEl) return;

  function toISODate(d) {
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
  }

  function calcHasta() {
    const meses = parseInt(mesesEl.value || "1", 10);
    const desdeVal = desdeEl.value;

    const base = desdeVal ? new Date(desdeVal + "T00:00:00") : new Date();
    const dias = meses * 30;

    const hasta = new Date(base);
    hasta.setDate(hasta.getDate() + dias);

    hastaEl.value = toISODate(hasta);
  }

  // set defaults
  if (!desdeEl.value) {
    const hoy = new Date();
    desdeEl.value = toISODate(hoy);
  }
  calcHasta();

  mesesEl.addEventListener("change", calcHasta);
  desdeEl.addEventListener("change", calcHasta);
})();
