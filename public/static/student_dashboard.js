const sidebar = document.getElementById("sidebar");
const menuToggle = document.getElementById("menuToggle");

menuToggle.addEventListener("click", function () {
    sidebar.classList.toggle("open");
});

document.addEventListener("click", function (event) {

    if (
        window.innerWidth <= 760 &&
        sidebar.classList.contains("open") &&
        !sidebar.contains(event.target) &&
        !menuToggle.contains(event.target)
    ) {
        sidebar.classList.remove("open");
    }

});

document.addEventListener("DOMContentLoaded", function () {
    const logoutLinks = document.querySelectorAll("[data-confirm-logout]");

    logoutLinks.forEach(function (link) {
        link.addEventListener("click", function (event) {
            const confirmed = confirm("Log out?");

            if (!confirmed) {
                event.preventDefault();
            }
        });
    });
});
