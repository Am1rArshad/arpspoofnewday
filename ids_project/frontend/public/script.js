document.addEventListener('DOMContentLoaded', () => {
  // Smooth scroll offset handling for sticky header
  const navLinks = document.querySelectorAll('.nav-menu a, .hero-actions a[href^="#"]');

  navLinks.forEach(link => {
    link.addEventListener('click', function(e) {
      const targetId = this.getAttribute('href');
      if (targetId && targetId.startsWith('#')) {
        e.preventDefault();
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
          const navHeight = document.querySelector('.nav-bar').offsetHeight;
          const elementPosition = targetElement.getBoundingClientRect().top;
          const offsetPosition = elementPosition + window.pageYOffset - navHeight - 20;

          window.scrollTo({
            top: offsetPosition,
            behavior: 'smooth'
          });
        }
      }
    });
  });

  // Highlight active link in navbar during scroll
  const sections = document.querySelectorAll('section[id]');
  window.addEventListener('scroll', () => {
    const scrollY = window.pageYOffset;
    const navHeight = document.querySelector('.nav-bar').offsetHeight;

    sections.forEach(current => {
      const sectionHeight = current.offsetHeight;
      const sectionTop = current.offsetTop - navHeight - 80;
      const sectionId = current.getAttribute('id');
      const matchedLink = document.querySelector(`.nav-menu a[href*="${sectionId}"]`);

      if (matchedLink) {
        if (scrollY > sectionTop && scrollY <= sectionTop + sectionHeight) {
          matchedLink.style.color = 'var(--accent)';
        } else {
          matchedLink.style.color = '';
        }
      }
    });
  });
});