
document.addEventListener("DOMContentLoaded", function () {

    let cameraStream = null;

    const video = document.getElementById("cameraPreview");
    const canvas = document.getElementById("photoCanvas");
    const cameraPhoto = document.getElementById("cameraPhoto");

    const cameraStatus = document.getElementById("cameraStatus");
    const locationStatus = document.getElementById("locationStatus");

    const latitude = document.getElementById("latitude");
    const longitude = document.getElementById("longitude");

    const startCameraButton = document.getElementById("startCamera");
    const capturePhotoButton = document.getElementById("capturePhoto");
    const attendanceForm = document.getElementById("attendanceForm");

    // Start camera
    startCameraButton.addEventListener("click", async function () {

        try {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                throw new Error("Camera is not supported by this browser.");
            }

            if (cameraStream) {
                cameraStream.getTracks().forEach(track => track.stop());
            }

            cameraStream = await navigator.mediaDevices.getUserMedia({
                video: {
                    facingMode: "user"
                },
                audio: false
            });

            video.srcObject = cameraStream;

            cameraStatus.textContent = "Camera ready. Capture a photo.";

            cameraPhoto.value = "";

        } catch (error) {
            cameraStatus.textContent =
                "Camera access failed. Use HTTPS or localhost and allow camera permission.";
        }
    });

    // Capture photo
    capturePhotoButton.addEventListener("click", function () {

        if (!video.videoWidth) {
            cameraStatus.textContent = "Start the camera first.";
            return;
        }

        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;

        const context = canvas.getContext("2d");

        context.drawImage(
            video,
            0,
            0,
            canvas.width,
            canvas.height
        );

        cameraPhoto.value = canvas.toDataURL("image/jpeg", 0.75);

        cameraStatus.textContent = "Photo captured successfully.";
    });

    // Capture browser location
    if (navigator.geolocation) {

        locationStatus.textContent = "Getting your location...";

        navigator.geolocation.getCurrentPosition(

            function (position) {

                latitude.value = position.coords.latitude;
                longitude.value = position.coords.longitude;

                locationStatus.textContent =
                    "Location captured (accuracy approx. " +
                    Math.round(position.coords.accuracy) +
                    " m).";
            },

            function () {

                locationStatus.textContent =
                    "Could not get location. Allow location permission and reload.";
            },

            {
                enableHighAccuracy: true,
                timeout: 15000
            }
        );

    } else {

        locationStatus.textContent =
            "This browser does not support location.";
    }

    // Validate before submitting
    attendanceForm.addEventListener("submit", function (event) {

        if (
            !cameraPhoto.value ||
            !latitude.value ||
            !longitude.value
        ) {
            event.preventDefault();

            alert(
                "Start camera, capture a photo, and allow location before submitting."
            );
        }
    });

    // Stop camera when leaving the page
    window.addEventListener("pagehide", function () {

        if (cameraStream) {
            cameraStream.getTracks().forEach(track => track.stop());
        }
    });

});
