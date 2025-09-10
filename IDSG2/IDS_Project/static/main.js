// Dynamic greeting
window.onload = function() {
    const hour = new Date().getHours();
    let greet = 'Welcome';
    if (hour < 12) greet = 'Good Morning';
    else if (hour < 18) greet = 'Good Afternoon';
    else greet = 'Good Evening';
    document.getElementById('greeting').innerText = greet + ', to the Intrusion Detection System!';
};
