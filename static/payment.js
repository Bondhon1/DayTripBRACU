document.addEventListener('DOMContentLoaded', () => {
  function updateAmount(selectElement, amountDisplay, baseAmount, bkashCharge, nagadCharge) {
    selectElement.addEventListener('change', () => {
      let charge = selectElement.value === 'Bkash' ? bkashCharge : nagadCharge;
      amountDisplay.textContent = 'Amount: ' + (baseAmount + charge);
    });
  }

  const preMethod = document.getElementById('methodPre');
  if (preMethod) {
    const amountDisplay = document.getElementById('amount-display');
    updateAmount(preMethod, amountDisplay, 500, 10, 5);
  }

  const remMethod = document.getElementById('methodRem');
  if (remMethod) {
    const amountDisplay = document.getElementById('amount-display');
    updateAmount(remMethod, amountDisplay, 1500, 28, 13);
  }

  const fullMethod = document.getElementById('methodFull');
  if (fullMethod) {
    const amountDisplay = document.getElementById('amount-display');
    updateAmount(fullMethod, amountDisplay, 2000, 38, 18);
  }
});
