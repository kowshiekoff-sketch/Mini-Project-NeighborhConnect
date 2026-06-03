const roleSelect = document.querySelector("#roleSelect");
const providerFields = document.querySelectorAll(".provider-only");
const adminFields = document.querySelectorAll(".admin-only");

function syncProviderFields() {
  if (!roleSelect) return;
  providerFields.forEach((field) => {
    field.classList.toggle("d-none", roleSelect.value !== "provider");
  });
  adminFields.forEach((field) => {
    field.classList.toggle("d-none", roleSelect.value !== "admin");
  });
}

if (roleSelect) {
  roleSelect.addEventListener("change", syncProviderFields);
  syncProviderFields();
}

const dateInputs = document.querySelectorAll('input[type="date"]');
const today = new Date().toISOString().split("T")[0];
dateInputs.forEach((input) => {
  if (!input.min) input.min = today;
});
