document.addEventListener('DOMContentLoaded', function () {
    // Get the input element
    var input = document.getElementById('picture-input');
    
    // Get the preview image element
    var previewImage = document.getElementById('preview-image');
  
    // Listen for changes in the input field
    input.addEventListener('change', function () {
      var file = input.files[0];
  
      // Check if a file is selected
      if (file) {
        // Create a FileReader object
        var reader = new FileReader();
  
        // Set up the FileReader onload event
        reader.onload = function (e) {
          // Set the preview image source
          previewImage.src = e.target.result;
          // Display the preview image
          previewImage.style.display = 'block';
        };
  
        // Read the selected file as a data URL
        reader.readAsDataURL(file);
      } else {
        // Hide the preview image if no file is selected
        previewImage.style.display = 'none';
      }
    });
  });
  