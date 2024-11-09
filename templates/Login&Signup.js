function flipCard(toSignUp) {
  const card = document.getElementById('card');
  if (toSignUp) {
      card.classList.add('flip'); // Flip to signup
  } else {
      card.classList.remove('flip'); // Flip to login
  }
}
document.getElementById('signup-link').addEventListener('click', function(e) {
  e.preventDefault(); // Prevent default action of the link
  document.getElementById('card').classList.add('flip'); // Flip to signup card
});

document.getElementById('login-link').addEventListener('click', function(e) {
  e.preventDefault(); // Prevent default action of the link
  document.getElementById('card').classList.remove('flip'); // Flip back to login card
});
