"use client";

import { useEffect, useRef, useState } from "react";
import createGlobe from "cobe";
import ErrorBoundary from '../ErrorBoundary';

interface GlobeProps {
  className?: string;
}

export const Globe = ({ className }: GlobeProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [mounted, setMounted] = useState(false);
  const pointerInteracting = useRef<number | null>(null);
  const pointerInteractionMovement = useRef(0);
  const phi = useRef(0);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted || !canvasRef.current) return;

    let width = 600;
    const globe = createGlobe(canvasRef.current, {
      devicePixelRatio: 2,
      width: width * 2,
      height: width * 2,
      phi: 0,
      theta: 0.3,
      dark: 1,
      diffuse: 1.2,
      mapSamples: 16000,
      mapBrightness: 6,
      baseColor: [0.3, 0.3, 0.3],
      markerColor: [0.1, 0.8, 1],
      glowColor: [1, 1, 1],
      markers: [
        { location: [37.7595, -122.4367], size: 0.03 },
        { location: [40.7128, -74.006], size: 0.1 },
        { location: [51.5074, -0.1278], size: 0.05 },
      ],
      onRender: (state) => {
        state.phi = phi.current;
        phi.current += 0.005;
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

    // Add event listeners
    canvasRef.current.addEventListener('pointerdown', onPointerDown);
    canvasRef.current.addEventListener('pointerup', onPointerUp);
    canvasRef.current.addEventListener('pointerout', onPointerOut);
    canvasRef.current.addEventListener('mousemove', onMouseMove as any);
    canvasRef.current.addEventListener('touchmove', onMouseMove as any);

    return () => {
      globe.destroy();
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
          transition: "opacity 1s ease"
        }}
        className={className}
      />
    </ErrorBoundary>
  );
};

export default Globe;