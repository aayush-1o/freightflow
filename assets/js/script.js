// FreightFlow - Main JavaScript
// ATTENTION: Fully optimized version

console.log("🚀 script.js loaded");

// ========================================
// MOBILE MENU & SMOOTH SCROLL
// ========================================
document.addEventListener("DOMContentLoaded", () => {

    const mobileMenuBtn = document.getElementById("mobile-menu-btn");
    const mobileMenu = document.getElementById("mobile-menu");

    if (mobileMenuBtn && mobileMenu) {
        mobileMenuBtn.addEventListener("click", () => {
            mobileMenu.classList.toggle("hidden");
        });
    }

    document.querySelectorAll('a[href^="#"]').forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const target = document.querySelector(link.getAttribute("href"));
            if (target) target.scrollIntoView({ behavior: "smooth" });
            if (mobileMenu) mobileMenu.classList.add("hidden");
        });
    });
});

// ========================================
// SESSION HELPERS
// ========================================
function saveUserSession(user) {
    localStorage.setItem("freightflow_current_user", JSON.stringify(user));
}

function getCurrentUser() {
    const u = localStorage.getItem("freightflow_current_user");
    return u ? JSON.parse(u) : null;
}

function logoutUser() {
    localStorage.removeItem("freightflow_current_user");
    window.location.href = "../index.html";
}

// Corrected redirect paths
function redirectToDashboard(role) {
    const dashboards = {
        shipper: "shipper-dashboard.html",
        driver: "driver-dashboard.html",
        admin: "admin-dashboard.html"
    };

    if (dashboards[role]) {
        window.location.href = dashboards[role];
    }
}

// ========================================
// REGISTER FORM HANDLER
// ========================================
document.addEventListener("DOMContentLoaded", () => {

    const registerForm = document.getElementById("register-form");

    if (registerForm) {

        console.log("✔ Register form found");

        registerForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const fullname = document.getElementById("fullname").value.trim();
            const email = document.getElementById("email").value.trim();
            const phone = document.getElementById("phone").value.trim();
            const role = document.getElementById("role").value.trim();
            const password = document.getElementById("password").value.trim();
            const confirmPassword = document.getElementById("confirm-password").value.trim();

            const errorBox = document.getElementById("error-message");
            const successBox = document.getElementById("success-message");

            errorBox.classList.add("hidden");
            successBox.classList.add("hidden");

            if (password !== confirmPassword) {
                errorBox.textContent = "Passwords do not match!";
                errorBox.classList.remove("hidden");
                return;
            }

            try {
                const res = await fetch("http://localhost:5000/api/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        name: fullname,
                        email,
                        phone,
                        role,
                        password
                    }),
                });

                const data = await res.json();

                if (!res.ok) {
                    errorBox.textContent = data.message || "Registration failed.";
                    errorBox.classList.remove("hidden");
                    return;
                }

                successBox.textContent = "Account created! Redirecting...";
                successBox.classList.remove("hidden");

                setTimeout(() => {
                    window.location.href = "login.html";
                }, 1500);

            } catch (err) {
                console.error(err);
                errorBox.textContent = "Network error. Try again.";
                errorBox.classList.remove("hidden");
            }
        });
    }
});

// ========================================
// LOGIN FORM HANDLER
// ========================================
document.addEventListener("DOMContentLoaded", () => {

    const loginForm = document.getElementById("login-form");

    if (loginForm) {

        console.log("✔ Login form found");

        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const email = document.getElementById("login-email").value.trim();
            const password = document.getElementById("login-password").value.trim();

            const errorBox = document.getElementById("login-error");
            errorBox.classList.add("hidden");

            try {
                const res = await fetch("http://localhost:5000/api/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, password }),
                });

                const data = await res.json();

                if (!res.ok) {
                    errorBox.textContent = data.message || "Invalid credentials.";
                    errorBox.classList.remove("hidden");
                    return;
                }

                saveUserSession(data.user);
                redirectToDashboard(data.user.role);

            } catch (err) {
                console.error(err);
                errorBox.textContent = "Network error. Try again.";
                errorBox.classList.remove("hidden");
            }
        });
    }
});
