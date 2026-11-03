
document.addEventListener("DOMContentLoaded", () => {

  // Logout confirmation
  document.querySelectorAll("[data-confirm-logout]").forEach((link) => {

    link.addEventListener("click", (event) => {

      const confirmLogout = window.confirm(
        "Are you sure you want to log out?"
      );

      if (!confirmLogout) {
        event.preventDefault();
      }

    });

  });

  // Highlight the current navigation item
  const currentPath = window.location.pathname.replace(/\/+$/, "");

  document.querySelectorAll(".nav a").forEach((link) => {

    try {

      const linkPath = new URL(
        link.href,
        window.location.origin
      ).pathname.replace(/\/+$/, "");

      if (linkPath === currentPath) {
        link.classList.add("active");
      } else if (link.textContent.trim().startsWith("Dashboard")) {
        link.classList.remove("active");
      }

    } catch (error) {
      // Ignore invalid navigation URLs.
    }

  });

});
