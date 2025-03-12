"use client";

import React, { useState, useEffect, useRef, useMemo } from "react";
import { cn } from "@/lib/utils";
import Image from "next/image";
import { motion } from "framer-motion";
import { Youtube } from "lucide-react";
import Link from "next/link";
import { Globe } from "./ui/Globe";

// Interfaces
interface FeatureCardProps {
  children?: React.ReactNode;
  className?: string;
  onClick?: () => void;
}

// Component definitions
const FeatureCard: React.FC<FeatureCardProps> = ({
  children,
  className,
  onClick,
}) => {
  return (
    <div 
      className={cn(`p-4 sm:p-8 relative overflow-hidden`, className)}
      onClick={onClick}
      role="button"
      tabIndex={0}
    >
      {children}
    </div>
  );
};

const FeatureTitle = ({ children }: { children: React.ReactNode }) => {
  return (
    <h3 className="font-bold text-xl md:text-2xl text-black dark:text-white">
      {children}
    </h3>
  );
};

const FeatureDescription = ({ children }: { children: React.ReactNode }) => {
  return (
    <p className="text-sm text-neutral-600 dark:text-neutral-300 mb-4">
      {children}
    </p>
  );
};

// Main component
export function FeaturesSectionDemo() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const features = [
    {
      title: "Track issues effectively",
      description: "Track and manage your project issues with ease using our intuitive interface.",
      skeleton: <SkeletonOne />,
      className: "col-span-1 lg:col-span-4 border-b lg:border-r dark:border-neutral-800",
    },
    {
      title: "Capture pictures with AI",
      description: "Capture stunning photos effortlessly using our advanced AI technology.",
      skeleton: <SkeletonTwo />,
      className: "border-b col-span-1 lg:col-span-2 dark:border-neutral-800",
    },
    {
      title: "Watch our AI on YouTube",
      description: "Whether its you or Tyler Durden, you can get to know about our product on YouTube",
      skeleton: <SkeletonThree />,
      className: "col-span-1 lg:col-span-3 lg:border-r dark:border-neutral-800",
    },
    {
      title: "Deploy in seconds",
      description: "Deploy your model in seconds with our state-of-the-art cloud services.",
      skeleton: <SkeletonFour />,
      className: "col-span-1 lg:col-span-3 border-b lg:border-none",
    },
  ];

  if (!mounted) {
    return (
      <div className="w-full h-screen animate-pulse bg-gray-200 dark:bg-gray-800" />
    );
  }

  return (
    <div className="relative z-20 py-10 lg:py-40 max-w-7xl mx-auto">
      <div className="px-8">
        <h4 className="text-3xl lg:text-5xl lg:leading-tight max-w-5xl mx-auto text-center tracking-tight font-medium text-black dark:text-white">
          Packed with thousands of features
        </h4>
        <p className="text-sm lg:text-base max-w-2xl my-4 mx-auto text-neutral-500 text-center font-normal dark:text-neutral-300">
          From Image generation to video generation, Everything AI has APIs for literally everything.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-6 mt-12 xl:border rounded-md dark:border-neutral-800">
        {features.map((feature) => (
          <FeatureCard key={feature.title} className={feature.className}>
            <FeatureTitle>{feature.title}</FeatureTitle>
            <FeatureDescription>{feature.description}</FeatureDescription>
            <div className="h-full w-full">{feature.skeleton}</div>
          </FeatureCard>
        ))}
      </div>
    </div>
  );
}

// Skeleton components
export const SkeletonOne: React.FC = () => {
  return (
    <div className="relative flex py-8 px-2 gap-10 h-full">
      <div className="w-full p-5 mx-auto bg-white dark:bg-neutral-900 shadow-2xl group h-full">
        <div className="flex flex-1 w-full h-full flex-col space-y-2">
          <Image
            src="/Attacked.jpg"
            alt="header"
            width={800}
            height={800}
            loading="lazy"
            className="h-full w-full aspect-square object-cover object-left-top rounded-sm"
          />
        </div>
      </div>
      <div className="absolute bottom-0 z-40 inset-x-0 h-60 bg-gradient-to-t from-white dark:from-black via-white dark:via-black to-transparent w-full pointer-events-none" />
      <div className="absolute top-0 z-40 inset-x-0 h-60 bg-gradient-to-b from-white dark:from-black via-transparent to-transparent w-full pointer-events-none" />
    </div>
  );
};

export const SkeletonTwo: React.FC = () => {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) return null;

  return (
    <div className="relative flex flex-col items-center justify-center p-8 h-full overflow-hidden bg-gradient-to-br from-purple-50 to-white dark:from-neutral-900 dark:to-neutral-800">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="text-center space-y-4"
      >
        {/* AI Icon and content */}
        <div className="relative w-16 h-16 mx-auto">
          <motion.div
            animate={{
              scale: [1, 1.2, 1],
              rotate: [0, 360],
            }}
            transition={{
              duration: 3,
              repeat: Infinity,
              ease: "linear",
            }}
            className="absolute inset-0 rounded-full bg-purple-500/30 blur-xl"
          />
          {/* ... rest of your SVG icon ... */}
        </div>
        
        <h3 className="text-xl font-bold text-gray-900 dark:text-white">
          AI Image Generation
        </h3>
        
        <motion.p 
          className="text-sm text-gray-600 dark:text-gray-300"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          Transform your ideas into stunning visuals with our advanced AI.
        </motion.p>

        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="flex gap-2 justify-center mt-4"
        >
          {['4K', 'HDR', 'Neural', 'Stable'].map((tag) => (
            <span
              key={tag}
              className="px-3 py-1 text-xs font-medium rounded-full bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400"
            >
              {tag}
            </span>
          ))}
        </motion.div>
      </motion.div>
    </div>
  );
};

export const SkeletonThree: React.FC = () => {
  return (
    <Link
      href="https://www.youtube.com/watch?v=RPa3_AD1_Vs"
      target="_blank"
      rel="noopener noreferrer"
      className="relative flex gap-10 h-full group/image"
    >
      <div className="w-full mx-auto bg-transparent dark:bg-transparent group h-full">
        <div className="flex flex-1 w-full h-full flex-col space-y-2 relative">
          <Youtube className="h-20 w-20 absolute z-10 inset-0 text-red-500 m-auto" />
          <Image
            src="https://assets.aceternity.com/fireship.jpg"
            alt="YouTube thumbnail"
            width={800}
            height={800}
            className="h-full w-full aspect-square object-cover object-center rounded-sm blur-none group-hover/image:blur-md transition-all duration-200"
          />
        </div>
      </div>
    </Link>
  );
};

export const SkeletonFour: React.FC = () => {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) return null;

  return (
    <div className="h-60 md:h-60 flex flex-col items-center relative bg-transparent dark:bg-transparent mt-10">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5 }}
      >
        <Globe className="absolute -right-10 md:-right-10 -bottom-80 md:-bottom-72" />
      </motion.div>
    </div>
  );
};
