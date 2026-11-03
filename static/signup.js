
// ========================================
// KREOPUGO - STUDENT SIGNUP JAVASCRIPT
// Batch matching based on College + Course
// ========================================

document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("signupForm");

    if (!form) {
        console.error("Signup form not found!");
        return;
    }

    const collegeInput = document.getElementById("college");
    const courseSelect = document.getElementById("course");
    const batchSelect = document.getElementById("batch");

    const batchMessage = document.getElementById("batchMessage");
    const password = document.getElementById("password");
    const confirmPassword = document.getElementById("confirm_password");
    const passwordMessage = document.getElementById("passwordMessage");
    const signupButton = document.getElementById("signupButton");

    // Flask endpoint supplied by signup.html
    const batchesUrl = form.dataset.batchesUrl;

    let requestNumber = 0;
    let collegeTimer = null;

    // ========================================
    // LOAD BATCHES MATCHING COLLEGE AND COURSE
    // ========================================

    async function loadBatches() {

        const college = collegeInput.value.trim();
        const course = courseSelect.value;

        const currentRequest = ++requestNumber;

        batchSelect.innerHTML = "";
        batchSelect.disabled = true;
        batchMessage.textContent = "";

        if (!college || !course) {

            batchSelect.add(
                new Option("Select college and course first", "")
            );

            batchMessage.textContent =
                "Enter your college name and select your course.";

            return;
        }

        batchSelect.add(
            new Option("Loading available batches...", "")
        );

        batchMessage.textContent = "Checking available batches...";

        try {

            const params = new URLSearchParams({
                college: college,
                course: course
            });

            const response = await fetch(
                batchesUrl + "?" + params.toString(),
                {
                    method: "GET",
                    headers: {
                        "Accept": "application/json"
                    }
                }
            );

            if (!response.ok) {
                throw new Error("Batch API returned " + response.status);
            }

            const batches = await response.json();

            // Ignore outdated requests
            if (currentRequest !== requestNumber) return;

            batchSelect.innerHTML = "";

            if (!Array.isArray(batches) || batches.length === 0) {

                batchSelect.add(
                    new Option("No matching batches available", "")
                );

                batchMessage.textContent =
                    "No available batch matches your college and course. Please contact your mentor.";

                return;
            }

            batchSelect.add(
                new Option("Select your batch", "")
            );

            batches.forEach(function (batch) {

                const label =
                    batch.batch_name +
                    " (" +
                    batch.academic_year +
                    " - Section " +
                    batch.section +
                    " - " +
                    batch.available +
                    " seats left)";

                // Submit the batch name through the existing batch_id field
                batchSelect.add(
                    new Option(label, batch.batch_name)
                );

            });

            batchSelect.disabled = false;

            batchMessage.textContent =
                batches.length + " matching batch(es) available.";

        } catch (error) {

            if (currentRequest !== requestNumber) return;

            console.error("Batch loading error:", error);

            batchSelect.innerHTML = "";

            batchSelect.add(
                new Option("Unable to load batches", "")
            );

            batchMessage.textContent =
                "Unable to load batches. Please refresh and try again.";
        }
    }

    // ========================================
    // COLLEGE AND COURSE CHANGE
    // ========================================

    collegeInput.addEventListener("input", function () {

        clearTimeout(collegeTimer);

        collegeTimer = setTimeout(function () {
            loadBatches();
        }, 350);

    });

    collegeInput.addEventListener("change", loadBatches);
    courseSelect.addEventListener("change", loadBatches);

    // ========================================
    // PASSWORD MATCH VALIDATION
    // ========================================

    function checkPasswords() {

        if (!confirmPassword.value) {
            passwordMessage.textContent = "";
            return true;
        }

        if (password.value !== confirmPassword.value) {

            passwordMessage.textContent =
                "Passwords do not match.";

            passwordMessage.style.color = "red";

            return false;
        }

        passwordMessage.textContent =
            "Passwords match.";

        passwordMessage.style.color = "green";

        return true;
    }

    password.addEventListener("input", checkPasswords);
    confirmPassword.addEventListener("input", checkPasswords);

    // ========================================
    // FORM SUBMISSION
    // ========================================

    form.addEventListener("submit", function (event) {

        if (!checkPasswords()) {

            event.preventDefault();
            confirmPassword.focus();

            return;
        }

        if (!batchSelect.value || batchSelect.disabled) {

            event.preventDefault();

            alert(
                "Please select an available batch matching your college and course."
            );

            batchSelect.focus();

            return;
        }

        if (signupButton) {
            signupButton.disabled = true;
            signupButton.textContent = "Creating Account...";
        }

    });

    // Load batches if college and course are already filled
    if (collegeInput.value.trim() && courseSelect.value) {
        loadBatches();
    }

});

// ========================================
// SHOW / HIDE PASSWORD
// ========================================

function togglePassword(inputId, button) {

    const input = document.getElementById(inputId);

    if (!input) return;

    if (input.type === "password") {

        input.type = "text";

        if (button) {
            button.textContent = "Hide";
        }

    } else {

        input.type = "password";

        if (button) {
            button.textContent = "Show";
        }

    }
}
