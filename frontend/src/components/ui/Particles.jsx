import React, { useEffect } from 'react';

const ParticlesBackground = () => {
  useEffect(() => {
    // Load particles.js from CDN
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js';
    script.async = true;
    
    script.onload = () => {
      // Initialize particles.js after the script is loaded
      if (window.particlesJS) {
        window.particlesJS('particles-js', {
          particles: {
            number: {
              value: 80,
              density: {
                enable: true,
                value_area: 800
              }
            },
            color: {
              value: '#3b82f6'
            },
            shape: {
              type: 'circle',
            },
            opacity: {
              value: 0.5,
              random: true,
            },
            size: {
              value: 3,
              random: true,
            },
            line_linked: {
              enable: true,
              distance: 150,
              color: '#3b82f6',
              opacity: 0.2,
              width: 1
            },
            move: {
              enable: true,
              speed: 2,
              direction: 'none',
              random: true,
              straight: false,
              out_mode: 'out',
              bounce: false,
            }
          },
          interactivity: {
            detect_on: 'canvas',
            events: {
              onhover: {
                enable: true,
                mode: 'grab'
              },
              onclick: {
                enable: true,
                mode: 'push'
              },
              resize: true
            },
            modes: {
              grab: {
                distance: 140,
                line_linked: {
                  opacity: 1
                }
              },
              push: {
                particles_nb: 4
              }
            }
          },
          retina_detect: true
        });
      }
    };

    // Add the script to the document
    document.body.appendChild(script);

    // Cleanup function
    return () => {
      // Remove the script when component unmounts
      if (document.body.contains(script)) {
        document.body.removeChild(script);
      }
      
      // Clear particles container
      const particles = document.getElementById('particles-js');
      if (particles) {
        particles.innerHTML = '';
      }
    };
  }, []);

  return (
    <div 
      id="particles-js" 
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,  // Changed from -1 to 0 to ensure it stays behind content
        pointerEvents: 'none',
        backgroundColor: 'transparent',
        opacity: 0.7  // Make particles slightly transparent
      }}
    />
  );
};

export default ParticlesBackground;
