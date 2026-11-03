// KREOPUGO Admin Dashboard JavaScript

document.addEventListener("DOMContentLoaded", function () {

    // Logout confirmation
    const logoutLinks = document.querySelectorAll(
        "[data-confirm-logout]"
    );

    logoutLinks.forEach(function (link) {

        link.addEventListener("click", function (event) {

            const confirmed = window.confirm("Log out?");

            if (!confirmed) {
                event.preventDefault();
            }

        });

    });

});