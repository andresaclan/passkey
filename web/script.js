document.getElementById('registerButton').addEventListener('click', register);
document.getElementById('loginButton').addEventListener('click', login);

function showMessage(message, isError) {
    const messageElement = document.getElementById('message');
    messageElement.textContent = message;
    messageElement.style.color = isError ? 'red' : 'green';
}

async function register() {
    console.log("starting registration");
    showMessage("registered", false)
}

async function login() {
    console.log("starting login");
    showMessage("logged in", false)
}