"use client";

import HeroParallaxDemo from "@/components/ui/hero-parallax-demo";
import Button from "@/components/ui/button";
import { FeaturesSectionDemo } from "@/components/Bentogrid";
import { FeaturesSectionDemo as FeaturesWithIcons } from "@/components/ui/infocard";

export default function Home() {
  return (
    <main className="min-h-screen flex flex-col items-center">
      {/* Hero section takes full width */}
      <section className="w-full">
        <HeroParallaxDemo />
      </section>
      
      {/* Features section */}
      <section className="w-full">
        <FeaturesSectionDemo/>
      </section>
      
      {/* Button centered */}
      <section className="flex justify-center w-full py-16">
        <Button />
      </section>
      
      {/* Icons Features section at the bottom */}
      <section className="w-full bg-white dark:bg-black py-16">
        <FeaturesWithIcons />
      </section>
    </main>
  );
}