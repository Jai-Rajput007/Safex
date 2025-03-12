"use client";
import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

// Sample data for the process cards
const processSteps = [
  {
    title: "Identify Threats",
    description: "We scan and identify potential phishing threats targeting your organization."
  },
  {
    title: "Analyze Patterns",
    description: "Our AI analyzes patterns to detect sophisticated phishing attempts."
  },
  {
    title: "Block Attacks",
    description: "We automatically block identified phishing attacks in real-time."
  },
  {
    title: "Educate Users",
    description: "We provide training to help your team recognize phishing attempts."
  },
  {
    title: "Monitor Activity",
    description: "Continuous monitoring ensures ongoing protection against new threats."
  },
  {
    title: "Regular Reports",
    description: "Detailed reports keep you informed about your security status."
  }
];

export default function PhisingCards() {
  // State to track which step we're currently on (0-based index)
  const [currentStep, setCurrentStep] = useState(0);

  // Function to advance to the next step
  const nextStep = () => {
    if (currentStep < processSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      // Reset to beginning if we're at the end
      setCurrentStep(0);
    }
  };

  return (
    <motion.div
      className="w-full max-w-7xl mx-auto mt-32 mb-24 px-4 sm:px-6 lg:px-8"
      initial={{ opacity: 0, y: 40 }}
      animate={{ 
        opacity: 1, 
        y: 0,
        transition: {
          duration: 0.8,
          ease: "easeOut",
          delay: 0.6
        }
      }}
    >
      <div className="bg-gray-50 dark:bg-gray-900 rounded-xl shadow-xl overflow-hidden">
        {/* Card Header */}
        <div className="text-center pt-10 pb-6 px-4">
          <h2 className="text-2xl sm:text-3xl font-bold text-gray-800 dark:text-white">
            Here's how we can help you
          </h2>
          <div className="w-24 h-1 bg-red-500 mx-auto mt-4"></div>
        </div>

        {/* Card Content - Step by step reveal */}
        <div className="p-6 sm:p-10">
          {/* Always create space for two rows of cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 relative min-h-[400px]">
            {/* First row placeholder spaces */}
            <div className={`${currentStep >= 0 ? 'block' : 'hidden'}`}>
              <AnimatePresence>
                {currentStep >= 0 && (
                  <CardItem step={processSteps[0]} index={0} />
                )}
              </AnimatePresence>
            </div>
            
            <div className={`${currentStep >= 1 ? 'block' : 'hidden'}`}>
              <AnimatePresence>
                {currentStep >= 1 && (
                  <CardItem step={processSteps[1]} index={1} />
                )}
              </AnimatePresence>
            </div>
            
            <div className={`${currentStep >= 2 ? 'block' : 'hidden'}`}>
              <AnimatePresence>
                {currentStep >= 2 && (
                  <CardItem step={processSteps[2]} index={2} />
                )}
              </AnimatePresence>
            </div>
            
            {/* Second row placeholder spaces */}
            <div className={`${currentStep >= 3 ? 'block' : 'hidden'}`}>
              <AnimatePresence>
                {currentStep >= 3 && (
                  <CardItem step={processSteps[3]} index={3} />
                )}
              </AnimatePresence>
            </div>
            
            <div className={`${currentStep >= 4 ? 'block' : 'hidden'}`}>
              <AnimatePresence>
                {currentStep >= 4 && (
                  <CardItem step={processSteps[4]} index={4} />
                )}
              </AnimatePresence>
            </div>
            
            <div className={`${currentStep >= 5 ? 'block' : 'hidden'}`}>
              <AnimatePresence>
                {currentStep >= 5 && (
                  <CardItem step={processSteps[5]} index={5} />
                )}
              </AnimatePresence>
            </div>
          </div>
          
          {/* Next step button */}
          <div className="flex justify-center mt-10">
            <motion.button
              className="bg-red-500 hover:bg-red-600 text-white rounded-full w-12 h-12 flex items-center justify-center shadow-lg"
              onClick={nextStep}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.95 }}
              animate={{
                x: [0, 5, 0],
                transition: {
                  duration: 1.5,
                  repeat: Infinity,
                  repeatType: "loop"
                }
              }}
            >
              {currentStep < processSteps.length - 1 ? (
                <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              )}
            </motion.button>
          </div>
          
          {/* Progress indicator */}
          <div className="flex justify-center mt-4">
            <div className="flex space-x-2">
              {processSteps.map((_, index) => (
                <div 
                  key={index} 
                  className={`w-2 h-2 rounded-full ${
                    index <= currentStep ? 'bg-red-500' : 'bg-gray-300 dark:bg-gray-700'
                  }`}
                />
              ))}
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// Card component extracted for cleaner code
const CardItem = ({ step, index }) => {
  return (
    <motion.div
      className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 hover:shadow-lg transition-all duration-300 relative z-10"
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ 
        opacity: 1, 
        y: 0,
        scale: 1,
        transition: {
          duration: 0.5,
          ease: "easeOut"
        }
      }}
      exit={{ opacity: 0, scale: 0.9 }}
      whileHover={{
        y: -5,
        boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)",
        transition: { duration: 0.2 }
      }}
    >
      {/* Card content */}
      <div className="flex items-start">
        <div className="flex-shrink-0 bg-red-100 dark:bg-red-900 rounded-lg p-3">
          <div className="w-8 h-8 bg-red-500 rounded-full flex items-center justify-center text-white font-bold">
            {index + 1}
          </div>
        </div>
        <div className="ml-4">
          <h3 className="text-lg font-semibold text-gray-800 dark:text-white">
            {step.title}
          </h3>
          <p className="mt-2 text-gray-600 dark:text-gray-300">
            {step.description}
          </p>
        </div>
      </div>
    </motion.div>
  );
}; 