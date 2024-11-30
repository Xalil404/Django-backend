//Code to show registration fields by email

document.addEventListener('DOMContentLoaded', function() {
    var emailButton = document.getElementById('email-button');
    var emailFields = document.getElementById('email-fields');
    var signupButton = document.getElementById('signup-button');

    emailButton.addEventListener('click', function() {
        if (emailFields.style.display === 'none') {
            emailFields.style.display = 'block';
            signupButton.style.display = 'block'; // Show the Sign Up button
            emailButton.style.display = 'none'; // Optionally hide the Continue with Email button
        }
    });
});
