document.addEventListener("DOMContentLoaded", function () {

    const reviewForms = document.querySelectorAll("[data-confirm-review]");

    reviewForms.forEach(function (form) {

        form.addEventListener("submit", function (event) {

            const submitButton = event.submitter;
            const decision = submitButton
                ? submitButton.value
                : "review";

            const message = decision === "Approved"
                ? "Are you sure you want to approve this submission?"
                : "Are you sure you want to reject this submission?";

            if (!confirm(message)) {
                event.preventDefault();
            }

        });

    });

});