"use client";

import dynamic from 'next/dynamic';
import { Heart } from "lucide-react";
import { useState, useEffect } from 'react';
import { Suspense } from 'react';
import { LoadingSection } from '@/components/ui/loading-spinner';

// Dynamic imports with loading states
const HeroParallaxDemo = dynamic(
  () => import("@/components/ui/hero-parallax-demo"), 
  { 
    ssr: false,
    loading: () => <LoadingSection />
  }
);

const FeaturesSectionDemo = dynamic(
  () => import("@/components/Bentogrid").then(mod => mod.FeaturesSectionDemo), 
  { 
    ssr: false, 
    loading: () => <LoadingSection />
  }
);

const FeaturesWithIcons = dynamic(
  () => import("@/components/ui/infocard").then(mod => mod.FeaturesSectionDemo), 
  { 
    ssr: false,
    loading: () => <LoadingSection />
  }
);

const Button = dynamic(
  () => import("@/components/ui/button").then(mod => mod.Button), 
  { 
    ssr: false,
    loading: () => <div className="h-12 w-32 bg-gray-200 dark:bg-gray-800 rounded-md animate-pulse"></div>
  }
);

const Socials = dynamic(
  () => import("@/components/ui/Socials").then(mod => mod.Socials), 
  { 
    ssr: false,
    loading: () => <div className="h-8 w-32 bg-gray-200 dark:bg-gray-800 rounded-md animate-pulse"></div>
  }
);

export default function Home() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    // Use a timeout to prevent hydration issues
    const timer = setTimeout(() => {
      setMounted(true);
    }, 10);
    
    return () => clearTimeout(timer);
  }, []);

  if (!mounted) {
    return <LoadingSection className="h-screen" />;
  }

  return (
    <main className="min-h-screen flex flex-col items-center">
      <Suspense fallback={<LoadingSection />}>
        <section className="w-full">
          <HeroParallaxDemo />
        </section>
      </Suspense>
      
      <Suspense fallback={<LoadingSection />}>
        <section className="w-full">
          <FeaturesSectionDemo />
        </section>
      </Suspense>
      
      <Suspense fallback={<LoadingSection />}>
        <section className="flex justify-center w-full py-8">
          <Button />
        </section>
      </Suspense>
      
      <Suspense fallback={<LoadingSection />}>
        <section className="w-full bg-white dark:bg-black py-16">
          <FeaturesWithIcons />
        </section>
      </Suspense>
      
      <section className="w-full py-12 px-6 md:px-10 relative">
        <div className="max-w-7xl mx-auto">
          <div className="relative w-full h-px bg-purple-500 opacity-80 before:content-[''] before:absolute before:inset-0 before:blur-sm before:bg-purple-400 after:content-[''] after:absolute after:inset-0 after:blur-md after:bg-purple-600"></div>
          
          <div className="mt-8 flex flex-col md:flex-row justify-between items-center py-4">
            <div className="text-center md:text-left mb-6 md:mb-0">
              <h3 className="text-xl font-semibold text-purple-500 mb-2 flex items-center justify-center md:justify-start gap-2">
                <Heart size={18} className="text-purple-500" fill="currentColor" /> 
                Liked the Product?
              </h3>
              <p className="text-gray-700 dark:text-gray-300">Follow us on</p>
              <Suspense fallback={<div className="h-8 w-32 bg-gray-200 dark:bg-gray-800 rounded-md animate-pulse"></div>}>
                <Socials className="mt-4" />
              </Suspense>
            </div>
            
            <div className="text-center md:text-right">
              <h3 className="text-xl font-semibold text-purple-500 mb-2">Made By</h3>
              <p className="text-gray-700 dark:text-gray-300">Jai Singh Rajput</p>
              <p className="text-gray-700 dark:text-gray-300">Himanshi Satwani</p>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}