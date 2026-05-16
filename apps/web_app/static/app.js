const tokenKey = "custom-auth-token";
const message = document.querySelector("#message");
const tabs = document.querySelectorAll(".tab");
const loginForm = document.querySelector("#login-form");
const registerForm = document.querySelector("#register-form");
const sessionPanel = document.querySelector("#session-panel");
const userName = document.querySelector("#user-name");
const userEmail = document.querySelector("#user-email");
const roles = document.querySelector("#roles");
const logoutButton = document.querySelector("#logout-button");
const deactivateButton = document.querySelector("#deactivate-button");

function setMessage(text, type = "") {
  message.textContent = text;
  message.className = `message ${type}`.trim();
}

function getToken() {
  return localStorage.getItem(tokenKey);
}

function setToken(token) {
  localStorage.setItem(tokenKey, token);
}

function clearToken() {
  localStorage.removeItem(tokenKey);
}

function formPayload(form) {
  return Object.fromEntries(new FormData(form).entries());
}

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const token = getToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(path, { ...options, headers });
  if (response.status === 204) {
    return null;
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || data.error || "Не удалось выполнить запрос");
  }
  return data;
}

function showAuthenticated(user) {
  loginForm.classList.remove("active");
  registerForm.classList.remove("active");
  sessionPanel.classList.remove("hidden");
  tabs.forEach((tab) => tab.classList.remove("active"));
  userName.textContent = `${user.last_name} ${user.first_name}`.trim() || user.email;
  userEmail.textContent = user.email;
  roles.innerHTML = user.roles.map((role) => `<span>${role}</span>`).join("");
}

function showAnonymous(tabName = "login") {
  sessionPanel.classList.add("hidden");
  tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === tabName));
  loginForm.classList.toggle("active", tabName === "login");
  registerForm.classList.toggle("active", tabName === "register");
}

async function restoreSession() {
  if (!getToken()) {
    showAnonymous();
    return;
  }

  try {
    const data = await request("/api/me");
    showAuthenticated(data.user);
    setMessage("Сессия восстановлена", "success");
  } catch (error) {
    clearToken();
    showAnonymous();
    setMessage("Сессия истекла, войдите снова", "error");
  }
}

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    setMessage("");
    showAnonymous(tab.dataset.tab);
  });
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage("Проверяем данные…");
  try {
    const data = await request("/api/login", {
      method: "POST",
      body: JSON.stringify(formPayload(loginForm)),
    });
    setToken(data.token);
    showAuthenticated(data.user);
    setMessage("Вы вошли в систему", "success");
  } catch (error) {
    setMessage(error.message, "error");
  }
});

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage("Создаем аккаунт…");
  try {
    await request("/api/register", {
      method: "POST",
      body: JSON.stringify(formPayload(registerForm)),
    });
    const payload = formPayload(registerForm);
    const data = await request("/api/login", {
      method: "POST",
      body: JSON.stringify({ email: payload.email, password: payload.password }),
    });
    setToken(data.token);
    showAuthenticated(data.user);
    registerForm.reset();
    setMessage("Аккаунт создан, вы авторизованы", "success");
  } catch (error) {
    setMessage(error.message, "error");
  }
});

logoutButton.addEventListener("click", async () => {
  setMessage("Завершаем сессию…");
  try {
    await request("/api/logout", { method: "POST" });
  } finally {
    clearToken();
    showAnonymous();
    setMessage("Вы вышли из аккаунта", "success");
  }
});

deactivateButton.addEventListener("click", async () => {
  const confirmed = window.confirm("Отключить учётку? Аккаунт останется в базе, но войти больше не получится.");
  if (!confirmed) {
    return;
  }

  setMessage("Отключаем учётку…");
  try {
    await request("/api/account", { method: "DELETE" });
    clearToken();
    showAnonymous();
    setMessage("Учётка отключена", "success");
  } catch (error) {
    setMessage(error.message, "error");
  }
});

restoreSession();
