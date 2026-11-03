document.addEventListener("DOMContentLoaded", function () {

    const course = document.getElementById("batch_course");
    const year = document.getElementById("academic_year");
    const section = document.getElementById("section");
    const batch = document.getElementById("batch_name");

    // Stop if this script is loaded on another page.
    if (!course || !year || !section || !batch) {
        return;
    }

    function updateBatch() {

        const selectedYear = year.value;

        if (course.value && selectedYear && section.value) {

            const startingYear = selectedYear.split("-")[0];

            batch.value =
                course.value + "-" +
                startingYear + "-" +
                section.value;

        } else {

            batch.value = "";

        }
    }

    course.addEventListener("change", updateBatch);
    year.addEventListener("change", updateBatch);
    section.addEventListener("change", updateBatch);

    updateBatch();

});