function handleThemeChange(theme) {
    // Remove existing theme classes from body and navbar
    document.body.classList.remove('light-theme', 'dark-theme', 'sepia-theme', 'sunrise-theme', 'valentine-theme', 'forest-theme');
    document.querySelector('.navbar').classList.remove('light-theme', 'dark-theme', 'sepia-theme', 'sunrise-theme', 'valentine-theme', 'forest-theme');

    // Add the appropriate theme class based on the button clicked
    switch (theme) {
        case 'light':
            document.body.classList.add('light-theme');
            document.querySelector('.navbar').classList.add('light-theme');
            break;
        case 'dark':
            document.body.classList.add('dark-theme');
            document.querySelector('.navbar').classList.add('dark-theme');
            break;
        case 'sepia':
            document.body.classList.add('sepia-theme');
            document.querySelector('.navbar').classList.add('sepia-theme');
            break;
        case 'sunrise':
            document.body.classList.add('sunrise-theme');
            document.querySelector('.navbar').classList.add('sunrise-theme');
            break;
        case 'valentine':
            document.body.classList.add('valentine-theme');
            document.querySelector('.navbar').classList.add('valentine-theme');
            break;
        case 'forest':
            document.body.classList.add('forest-theme');
            document.querySelector('.navbar').classList.add('forest-theme');
            break;
        default:
            break;
    }
}
