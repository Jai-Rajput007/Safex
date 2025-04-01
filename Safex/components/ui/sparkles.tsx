"use client";
import React, { useId, useMemo } from "react";
import { useEffect, useState } from "react";
import Particles, { initParticlesEngine } from "@tsparticles/react";
import type { Container, SingleOrMultiple } from "@tsparticles/engine";
import { loadSlim } from "@tsparticles/slim";
import { cn } from "@/lib/utils";
import { motion, useAnimation } from "framer-motion";

type ParticlesProps = {
  id?: string;
  className?: string;
  background?: string;
  particleSize?: number;
  minSize?: number;
  maxSize?: number;
  speed?: number;
  particleColor?: string;
  particleDensity?: number;
};
export const SparklesCore = (props: ParticlesProps) => {
  const {
    id,
    className,
    background,
    minSize,
    maxSize,
    speed,
    particleColor,
    particleDensity,
  } = props;
  const [init, setInit] = useState(false);
  
  // Use a memo to prevent unnecessary re-initialization
  const engineInitialized = React.useRef(false);
  
  useEffect(() => {
    if (!engineInitialized.current) {
      engineInitialized.current = true;
      initParticlesEngine(async (engine) => {
        await loadSlim(engine);
      }).then(() => {
        setInit(true);
      });
    } else {
      setInit(true);
    }
  }, []);
  
  const controls = useAnimation();

  const particlesLoaded = async (container?: Container) => {
    if (container) {
      controls.start({
        opacity: 1,
        transition: {
          duration: 1,
        },
      });
    }
  };

  // Use a memoized options object to prevent recalculations
  const options = useMemo(() => ({
    background: {
      color: {
        value: background || "#0d47a1",
      },
    },
    fullScreen: {
      enable: false,
      zIndex: 1,
    },
    fpsLimit: 60, // Lower FPS limit
    interactivity: {
      events: {
        onClick: {
          enable: false, // Disable clicking to improve performance
          mode: "push" as const,
        },
        onHover: {
          enable: false,
          mode: "repulse" as const,
        },
        resize: true as any,
      },
      modes: {
        push: {
          quantity: 2, // Reduced from 4
        },
        repulse: {
          distance: 200,
          duration: 0.4,
        },
      },
    },
    particles: {
      bounce: {
        horizontal: {
          value: 1,
        },
        vertical: {
          value: 1,
        },
      },
      collisions: {
        enable: false,
        maxSpeed: 50,
        mode: "bounce" as const,
        overlap: {
          enable: true,
          retries: 0,
        },
      },
      color: {
        value: particleColor || "#ffffff",
        animation: {
          h: {
            enable: false,
          },
          s: {
            enable: false,
          },
          l: {
            enable: false,
          },
        },
      },
      move: {
        angle: {
          offset: 0,
          value: 90,
        },
        attract: {
          enable: false,
        },
        direction: "none" as const,
        enable: true,
        outModes: {
          default: "out" as const,
        },
        random: false,
        size: false,
        speed: {
          min: 0.1,
          max: 1,
        },
        spin: {
          enable: false,
        },
        straight: false,
        trail: {
          enable: false,
        },
        vibrate: false,
        warp: false,
      },
      number: {
        density: {
          enable: true,
          width: 400,
          height: 400,
        },
        limit: {
          mode: "delete" as const,
          value: 100, // Add a particle limit
        },
        value: Math.min(particleDensity || 120, 80), // Cap particle density
      },
      opacity: {
        value: {
          min: 0.1,
          max: 1,
        },
        animation: {
          enable: true,
          speed: speed || 4,
          sync: false,
          mode: "auto" as const,
          startValue: "random" as const,
          destroy: "none" as const,
        },
      },
      shape: {
        type: "circle" as const,
      },
      size: {
        value: {
          min: minSize || 1,
          max: maxSize || 3,
        },
        animation: {
          enable: false,
        },
      },
      zIndex: {
        value: 0,
      },
    },
    detectRetina: false, // Disable retina detection for performance
  }), [background, minSize, maxSize, speed, particleColor, particleDensity]);

  const generatedId = useId();
  
  if (!init) {
    return (
      <motion.div className={cn("opacity-0", className)}>
        <div className="h-full w-full bg-transparent" />
      </motion.div>
    );
  }
  
  return (
    <motion.div animate={controls} className={cn("opacity-0", className)}>
      <Particles
        id={id || generatedId}
        className={cn("h-full w-full")}
        particlesLoaded={particlesLoaded}
        options={options}
      />
    </motion.div>
  );
};
