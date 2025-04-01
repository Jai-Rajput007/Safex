"use client";

import { useEffect, useRef, useState, memo } from "react";
import createGlobe from "cobe";
import ErrorBoundary from '../ErrorBoundary';

interface GlobeProps {
  className?: string;
}

// Wrap the component with memo to prevent unnecessary rerenders
export const Globe = memo(({ className }: GlobeProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [mounted, setMounted] = useState(false);
  const pointerInteracting = useRef<number | null>(null);
  const pointerInteractionMovement = useRef(0);
  const phi = useRef(0);
  const globeInstance = useRef<any>(null);
  const frameRef = useRef<number | null>(null);
  const isVisible = useRef(true);

  // Use intersection observer to only animate when visible
  useEffect(() => {
    if (!canvasRef.current) return;
    
    const observer = new IntersectionObserver((entries) => {
      const entry = entries[0];
      isVisible.current = entry.isIntersecting;
    }, { threshold: 0.1 });
    
    observer.observe(canvasRef.current);
    
    return () => {
      if (canvasRef.current) {
        observer.unobserve(canvasRef.current);
      }
    };
  }, [mounted]);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted || !canvasRef.current) return;

    let width = 600;
    // Use lower device pixel ratio for better performance
    const dpr = Math.min(window.devicePixelRatio, 1.5);
    
    globeInstance.current = createGlobe(canvasRef.current, {
      devicePixelRatio: dpr,
      width: width * 2,
      height: width * 2,
      phi: 0,
      theta: 0.3,
      dark: 1,
      diffuse: 1.2,
      mapSamples: 8000, // Reduced from 16000
      mapBrightness: 6,
      baseColor: [0.3, 0.3, 0.3],
      markerColor: [0.1, 0.8, 1],
      glowColor: [1, 1, 1],
      markers: [
        // Reduced markers for better performance
        { location: [40.7128, -74.006], size: 0.1 }
      ],
      onRender: (state) => {
        // Only animate when visible
        if (isVisible.current) {
          state.phi = phi.current;
          // Use slower rotation for better performance
          phi.current += 0.002;
        }
        state.width = width * 2;
        state.height = width * 2;
      }
    });

    const onPointerDown = (e: TouchEvent | MouseEvent) => {
      pointerInteracting.current = e instanceof TouchEvent ? e.touches[0].clientX : e.clientX;
      canvasRef.current!.style.cursor = 'grabbing';
    };

    const onPointerUp = () => {
      pointerInteracting.current = null;
      canvasRef.current!.style.cursor = 'grab';
    };

    const onPointerOut = () => {
      pointerInteracting.current = null;
      canvasRef.current!.style.cursor = 'grab';
    };

    const onMouseMove = (e: TouchEvent | MouseEvent) => {
      if (pointerInteracting.current !== null) {
        const clientX = e instanceof TouchEvent ? e.touches[0].clientX : e.clientX;
        const delta = (clientX - pointerInteracting.current) * 0.01;
        phi.current += delta;
        pointerInteracting.current = clientX;
      }
    };

    // Add event listeners with passive option for better performance
    canvasRef.current.addEventListener('pointerdown', onPointerDown, { passive: true });
    canvasRef.current.addEventListener('pointerup', onPointerUp, { passive: true });
    canvasRef.current.addEventListener('pointerout', onPointerOut, { passive: true });
    canvasRef.current.addEventListener('mousemove', onMouseMove as any, { passive: true });
    canvasRef.current.addEventListener('touchmove', onMouseMove as any, { passive: true });

    return () => {
      if (globeInstance.current) {
        globeInstance.current.destroy();
      }
      
      if (frameRef.current) {
        cancelAnimationFrame(frameRef.current);
      }
      
      canvasRef.current?.removeEventListener('pointerdown', onPointerDown);
      canvasRef.current?.removeEventListener('pointerup', onPointerUp);
      canvasRef.current?.removeEventListener('pointerout', onPointerOut);
      canvasRef.current?.removeEventListener('mousemove', onMouseMove as any);
      canvasRef.current?.removeEventListener('touchmove', onMouseMove as any);
    };
  }, [mounted]);

  if (!mounted) return null;

  return (
    <ErrorBoundary>
      <canvas
        ref={canvasRef}
        style={{
          width: 600,
          height: 600,
          maxWidth: "100%",
          aspectRatio: 1,
          cursor: "grab",
          contain: "layout paint size",
          opacity: mounted ? 1 : 0,
          transition: "opacity 1s ease",
          willChange: "transform" // Optimize for animations
        }}
        className={className}
      />
    </ErrorBoundary>
  );
});

Globe.displayName = "Globe";

export default Globe;