"use client";
import { LampContainer } from "@/components/ui/lamp";
import { motion } from "framer-motion";
import dynamic from 'next/dynamic';
import { useState, useEffect } from 'react';
import ReturnTop from '@/components/ui/Returntop';
import { FlipWords } from "@/components/ui/flip-words";
import ClickLight from "@/components/custom/click-light";
import ClickDarkNew from "@/components/custom/click-dark-new";

// Dynamically import components that might cause hydration issues
const ExpandableCardDemo = dynamic(
  () => import('@/components/expandable-card-demo-standard'),
  {
    ssr: false,
    loading: () => <div className="w-full h-32 animate-pulse bg-gray-200 dark:bg-gray-800 rounded-lg" /> 
  }
);

// Dynamically import theme-specific buttons to avoid hydration issues
const ThemeButton = dynamic(() => import('@/components/custom/theme-button'), {
  ssr: false,
  loading: () => <div className="w-[200px] h-[68px] animate-pulse bg-gray-200 dark:bg-gray-800 rounded-lg" />
});

const modules = [
  { title: "Injection Attacks" },
  { title: "Input Validation" },
  { title: "Cross-Site Scripting (XSS)" },
  { title: "Cross-Site Request Forgery (CSRF)" }
];

export default function LearnPage() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <main className="w-full min-h-screen flex flex-col bg-slate-950 dark:bg-slate-950">
      <LampContainer className="w-full flex-grow">
        <motion.div
          initial={{ opacity: 0.5, y: 100 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{
            delay: 0.3,
            duration: 0.8,
            ease: "easeInOut",
          }}
          className="mx-auto max-w-3xl text-center"
        >
          <h1 className="text-4xl font-bold text-white md:text-6xl lg:text-7xl">
            Learning Modules
          </h1>
          <p className="mt-4 text-gray-400">
            Explore our guides and documentation to master Safex features
          </p>
        </motion.div>
      </LampContainer>

      <div className="w-full h-24 bg-gradient-to-b from-slate-950 to-white dark:from-slate-950 dark:to-black"></div>

      <div className="w-full bg-white dark:bg-black">
        {modules.map((module, index) => (
          <motion.section
            key={module.title}
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: index * 0.1 }}
            className="py-12 px-4"
          >
            <h2 className="text-3xl font-semibold text-gray-900 dark:text-white text-center mb-8">       
              {module.title}
            </h2>
            <ExpandableCardDemo />
          </motion.section>
        ))}

        <div className="flex justify-center my-12">
          <ReturnTop />
        </div>

        {/* Flip Words Component */}
        <div className="flex flex-col items-center justify-center text-center my-16 px-4">
          <h3 className="text-2xl md:text-3xl font-bold text-gray-900 dark:text-white mb-6">
            Still not enough?
          </h3>
          <div className="text-xl md:text-2xl text-gray-700 dark:text-gray-300 flex items-center justify-center">
            <span className="inline-block">Talk to our Him.ai to</span>
            <FlipWords
              words={[
                "ask questions.",
                "solve issues.",
                "get guidance.",
                "learn more.",
                "explore more.",
                "clear doubts."
              ]}
              duration={2000}
              className="font-semibold ml-2 text-blue-600 dark:text-blue-400"
            />
          </div>
          
          {/* Theme Button - Using dynamic import to avoid hydration issues */}
          <div className="mt-8">
            <ThemeButton />
          </div>
        </div>
        
        {/* Additional space at the bottom */}
        <div className="h-24"></div>
      </div>
    </main>
  );
}