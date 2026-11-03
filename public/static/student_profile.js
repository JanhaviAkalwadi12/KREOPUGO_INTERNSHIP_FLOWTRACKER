
document.addEventListener("DOMContentLoaded", function () {

    const profileForm = document.getElementById("profileForm");
    const editButton = document.getElementById("editProfileButton");
    const cancelButton = document.getElementById("cancelProfileButton");
    const profileActions = document.getElementById("profileActions");
    const editHint = document.getElementById("editHint");

    const originalHint =
        "Your Student ID, college, course, batch and registration date are managed by your institute and cannot be changed here.";

    function enableProfileEditing() {
        if (!profileForm) return;

        profileForm.querySelectorAll('[data-editable="true"]').forEach(function (field) {
            field.readOnly = false;
        });

        profileActions.hidden = false;
        editButton.style.display = "none";

        editHint.textContent =
            "Edit the fields above, then choose Save Changes to confirm or Cancel to discard your edits.";

        document.getElementById("name").focus();
    }

    function cancelProfileEditing() {
        if (!profileForm) return;

        profileForm.reset();

        profileForm.querySelectorAll('[data-editable="true"]').forEach(function (field) {
            field.readOnly = true;
        });

        profileActions.hidden = true;
        editButton.style.display = "inline-block";
        editHint.textContent = originalHint;
    }

    if (editButton) {
        editButton.addEventListener("click", enableProfileEditing);
    }

    if (cancelButton) {
        cancelButton.addEventListener("click", cancelProfileEditing);
    }

    document.querySelectorAll("[data-password-target]").forEach(function (button) {
        button.addEventListener("click", function () {
            const inputId = button.dataset.passwordTarget;
            const passwordInput = document.getElementById(inputId);

            if (!passwordInput) return;

            const showing = passwordInput.type === "password";

            passwordInput.type = showing ? "text" : "password";
            button.textContent = showing ? "Hide" : "Show";

            button.setAttribute(
                "aria-label",
                showing ? "Hide password" : "Show password"
            );
        });
    });

});
