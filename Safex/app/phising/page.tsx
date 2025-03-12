"use client";
import React from "react";
import { motion } from "framer-motion";
import ColourfulText from "@/components/ui/colourful-text";
import PhisingCards from "@/components/PhisingCards";
import LinkCheckerForm from "@/components/LinkCheckerForm";

export default function PhisingPage() {
  return (
    <div className="min-h-screen w-full flex flex-col items-center relative overflow-hidden bg-white dark:bg-black ">
      <motion.h1 
        className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-center text-gray-800 dark:text-white relative z-2 font-sans px-4 mt-36"
        initial={{ opacity: 0, y: -20 }}
        animate={{ 
          opacity: 1, 
          y: 0,
          transition: {
            duration: 0.8,
            ease: "easeOut",
            delay: 0.3
          }
        }}
      >
        Annoyed with <ColourfulText text="fake" theme="red" /> or <ColourfulText text="phising" theme="red" /> sites?
      </motion.h1>

      {/* Process Cards */}
      <PhisingCards />
      
      {/* Link Checker Form */}
      <LinkCheckerForm />
    </div>
  );
}
