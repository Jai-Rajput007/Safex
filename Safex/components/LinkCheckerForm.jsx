"use client";
import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cover } from "@/components/ui/cover";
import { cn } from "@/lib/utils";
import { HoverBorderGradient } from "@/components/ui/hover-border-gradient";
import { MultiStepLoader } from "@/components/ui/multi-step-loader";

export default function LinkCheckerForm() {
  const [link, setLink] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [displayText, setDisplayText] = useState("");
  
  // Text to be generated character by character
  const resultsText = "Here's the Results";
  
  // Define loading states for MultiStepLoader
  const loadingStates = [
    { text: "Checking URL structure..." },
    { text: "Scanning for suspicious patterns..." },
    { text: "Verifying domain reputation..." },
    { text: "Analyzing SSL certificate..." },
    { text: "Checking for phishing indicators..." }
  ];
  
  // Only run on client-side to prevent hydration errors
  useEffect(() => {
    setMounted(true);
  }, []);
  
  // Handle text animation when results should be shown
  useEffect(() => {
    if (!showResults) {
      setDisplayText("");
      return;
    }
    
    let currentIndex = 0;
    const textInterval = setInterval(() => {
      if (currentIndex <= resultsText.length) {
        setDisplayText(resultsText.substring(0, currentIndex));
        currentIndex++;
      } else {
        clearInterval(textInterval);
      }
    }, 100);
    
    return () => clearInterval(textInterval);
  }, [showResults]);
  
  const handleSubmit = (e) => {
    e.preventDefault();
    
    // Only proceed if there's a link
    if (!link) return;
    
    // Handle form submission logic here
    console.log("Submitted link:", link);
    
    // Reset results and show loading
    setShowResults(false);
    setIsLoading(true);
    
    // Simulate processing time then show results
    setTimeout(() => {
      setIsLoading(false);
      setShowResults(true);
    }, 5000); // Longer duration to see the loader steps
  };

  // Custom Cover component with light theme support
  const CustomCover = ({ children, className }) => {
    return (
      <div className="relative">
        <Cover className={cn("text-xl md:text-2xl px-4 py-3", className)}>
          <span className="font-semibold text-gray-800 dark:text-white hover-white">
            {children}
          </span>
        </Cover>
        {/* Add an overlay to ensure text is visible in light mode */}
        <style jsx global>{`
          /* Override Cover component styles for light theme */
          .group\/cover:hover {
            background: #1e293b !important; /* slate-800 */
          }
          .group\/cover {
            background: white !important;
            border: 1px solid #e2e8f0 !important; /* slate-200 */
          }
          .dark .group\/cover {
            background: #0f172a !important; /* slate-900 */
            border: 1px solid #334155 !important; /* slate-700 */
          }
          /* Fix text visibility on hover */
          .group-hover\/cover\:text-white {
            color: white !important;
          }
          /* Force text to be white on hover */
          .group\/cover:hover span {
            color: white !important;
          }
          /* Add a custom class for hover state */
          .hover-white:hover {
            color: white !important;
          }
          /* Ensure beam animations are visible */
          .group\/cover:hover path {
            stroke-width: 2px !important;
            opacity: 1 !important;
          }
          /* Increase sparkles visibility */
          .group\/cover:hover .opacity-0 {
            opacity: 1 !important;
          }
        `}</style>
      </div>
    );
  };

  // Don't render anything until mounted to prevent hydration errors
  if (!mounted) {
    return null;
  }

  return (
    <>
      <div className="w-full max-w-7xl mx-auto mt-12 mb-24 px-4 sm:px-6 lg:px-8">
        {/* Card with animated border */}
        <div className="relative max-w-5xl mx-auto">
          {/* Animated border container */}
          <div className="absolute -inset-[1px] rounded-xl overflow-hidden">
            <div className="animated-border"></div>
          </div>
          
          {/* Card content */}
          <div className="relative z-10 backdrop-blur-sm bg-white/80 dark:bg-black/80 border border-transparent rounded-xl p-12 min-h-[400px] flex flex-col justify-center">
            {/* "Give it a try" text with Cover component */}
            <div className="absolute -top-8 left-8 z-20">
              <CustomCover>
                Give it a try
              </CustomCover>
            </div>
            
            {/* Input form */}
            <form onSubmit={handleSubmit} className="mt-10 w-full max-w-lg mx-auto">
              <div className="space-y-8">
                <div className="space-y-3">
                  <label className="text-base font-medium text-gray-700 dark:text-gray-300">
                    Suspicious Link
                  </label>
                  <div className="relative">
                    <input
                      type="url"
                      value={link}
                      onChange={(e) => setLink(e.target.value)}
                      className="flex h-12 w-full rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-black px-4 py-3 text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent transition-colors duration-200"
                      placeholder="Enter the suspected Link"
                      required
                    />
                    {!link && (
                      <div className="absolute inset-y-0 left-0 flex items-center pl-4 pointer-events-none">
                        <span className="text-gray-400 dark:text-gray-500">Enter the suspected Link</span>
                      </div>
                    )}
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Enter the link you want to check for phishing attempts.
                  </p>
                </div>
                
                <div className="flex justify-center">
                  <HoverBorderGradient
                    type="submit"
                    onClick={handleSubmit}
                    className="text-base font-medium py-2 px-8 text-gray-900 dark:text-white"
                    containerClassName="rounded-full"
                    duration={1}
                    as="button"
                    disabled={isLoading}
                  >
                    Submit
                  </HoverBorderGradient>
                </div>
                
                {/* Custom styles for animated border and HoverBorderGradient */}
                <style jsx global>{`
                  /* Light theme adjustments for HoverBorderGradient */
                  .bg-black/20 {
                    background-color: rgba(255, 255, 255, 0.2) !important; /* white with opacity */
                  }
                  .dark .bg-white/20 {
                    background-color: rgba(255, 255, 255, 0.2) !important;
                  }
                  
                  /* Button background */
                  .bg-black {
                    background-color: #ffffff !important; /* pure white */
                    border: 1px solid #e2e8f0 !important; /* light border for definition */
                  }
                  .dark .bg-black {
                    background-color: #000 !important; /* pure black */
                  }
                  
                  /* Fix animation visibility */
                  .flex-none {
                    opacity: 1 !important;
                    filter: blur(1px) !important;
                  }
                  
                  /* Ensure rounded corners */
                  .rounded-\\[100px\\] {
                    border-radius: 9999px !important;
                  }
                  
                  /* Enhance hover effect */
                  .hover\\:bg-black\\/10:hover {
                    background-color: rgba(255, 255, 255, 0.9) !important; /* slightly more opaque white */
                  }
                  .dark .hover\\:bg-black\\/10:hover {
                    background-color: rgba(0, 0, 0, 0.1) !important;
                  }
                  
                  /* Override text color */
                  button .text-white {
                    color: #111827 !important; /* gray-900 for light theme */
                  }
                  .dark button .text-white {
                    color: white !important; /* white for dark theme */
                  }
                  
                  /* Fix animation for light traveling across borders */
                  @keyframes gradientMove {
                    0% { background-position: 0% 0; }
                    100% { background-position: 200% 0; }
                  }
                  
                  /* Make sure the animation is visible and running */
                  [class*="HoverBorderGradient"] .flex-none {
                    animation: gradientMove 3s linear infinite !important;
                    background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.8), transparent) !important;
                    background-size: 200% 100% !important;
                    opacity: 0.8 !important;
                  }
                  
                  /* Enhance hover animation */
                  [class*="HoverBorderGradient"]:hover .flex-none {
                    animation: gradientMove 1.5s linear infinite !important;
                    background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 1), transparent) !important;
                    background-size: 200% 100% !important;
                    opacity: 1 !important;
                  }
                  
                  /* Fix z-index issues */
                  [class*="HoverBorderGradient"] > div {
                    z-index: 10 !important;
                  }
                  
                  /* Animated border for the card */
                  .animated-border {
                    position: absolute;
                    inset: 0;
                    border-radius: inherit;
                    padding: 1px;
                    background: linear-gradient(90deg, 
                      transparent 0%, 
                      rgba(59, 130, 246, 0.3) 25%, 
                      rgba(59, 130, 246, 0.8) 50%, 
                      rgba(59, 130, 246, 0.3) 75%, 
                      transparent 100%
                    );
                    background-size: 200% 100%;
                    background-position: 0% 0;
                    mask: 
                      linear-gradient(#fff 0 0) content-box, 
                      linear-gradient(#fff 0 0);
                    mask-composite: exclude;
                    -webkit-mask-composite: xor;
                    animation: borderAnimation 6s linear infinite;
                    opacity: 0.8;
                    filter: blur(1px);
                  }
                  
                  @keyframes borderAnimation {
                    0% {
                      background-position: 200% 0;
                    }
                    100% {
                      background-position: -200% 0;
                    }
                  }
                  
                  /* Enhance animation on hover */
                  .animated-border:hover {
                    animation-duration: 3s;
                    opacity: 1;
                  }
                  
                  /* Fix MultiStepLoader for light theme */
                  .dark .text-black {
                    color: white !important;
                  }
                  .text-black {
                    color: #111827 !important;
                  }
                  
                  /* Customize MultiStepLoader backdrop */
                  .backdrop-blur-2xl {
                    backdrop-filter: blur(16px) !important;
                    background-color: rgba(255, 255, 255, 0.5) !important;
                  }
                  .dark .backdrop-blur-2xl {
                    background-color: rgba(0, 0, 0, 0.5) !important;
                  }
                `}</style>
              </div>
            </form>
          </div>
        </div>
      </div>
      
      {/* MultiStepLoader component */}
      <MultiStepLoader 
        loadingStates={loadingStates}
        loading={isLoading}
        duration={1000}
        loop={false}
      />
      
      {/* Results section below the card */}
      {showResults && (
        <div className="w-full max-w-7xl mx-auto mt-8 mb-24 px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h2 className="text-4xl md:text-5xl font-bold text-gray-900 dark:text-white h-[60px]">
              {displayText}
              <span className="animate-pulse">|</span>
            </h2>
            
            {/* This space is reserved for future content */}
            <div className="mt-12 p-8 border border-gray-200 dark:border-gray-700 rounded-xl bg-white/90 dark:bg-black/90 backdrop-blur-sm">
              <p className="text-lg text-gray-700 dark:text-gray-300">
                Results will be displayed here.
              </p>
            </div>
          </div>
        </div>
      )}
    </>
  );
} 