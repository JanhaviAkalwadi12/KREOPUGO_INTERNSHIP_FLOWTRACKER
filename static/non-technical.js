
document.addEventListener("DOMContentLoaded", function () {

    // Logout confirmation
    const logoutLinks = document.querySelectorAll("[data-confirm-logout]");

    logoutLinks.forEach(function (link) {

        link.addEventListener("click", function (event) {

            const confirmed = window.confirm(
                "Are you sure you want to log out?"
            );

            if (!confirmed) {
                event.preventDefault();
            }

        });

    });

    // Highlight the active sidebar link
    const currentPath = window.location.pathname.replace(/\/+$/, "");

    const navLinks = document.querySelectorAll(".nav a");

    navLinks.forEach(function (link) {

        const linkPath = new URL(
            link.href,
            window.location.origin
        ).pathname.replace(/\/+$/, "");

        if (linkPath === currentPath) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }

    });

});
