"use client";
import React from "react";
import { motion } from "framer-motion";

interface ColourfulTextProps {
  text: string;
  theme?: "red" | "default";
}

const ColourfulText: React.FC<ColourfulTextProps> = ({ 
  text, 
  theme = "default" 
}) => {
  // Color palettes optimized for both light and dark modes
  const colors = theme === "red" 
    ? ["#ff0000", "#cc0000", "#990000", "#ff3333", "#cc3333", "#990033"]
    : ["#ff0000", "#00cc00", "#0000ff", "#cc6600", "#9900cc", "#cc0099"];

  return (
    <span className="inline-block font-bold">
      {text.split("").map((letter, index) => (
        <motion.span
          key={index}
          className="inline-block"
          animate={{
            color: colors,
            textShadow: theme === "red" 
              ? ["0 0 3px rgba(255,0,0,0.3)", "0 0 5px rgba(255,0,0,0.5)", "0 0 3px rgba(255,0,0,0.3)"]
              : ["0 0 3px rgba(0,0,255,0.3)", "0 0 5px rgba(0,0,255,0.5)", "0 0 3px rgba(0,0,255,0.3)"]
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            repeatType: "reverse",
          }}
        >
          {letter}
        </motion.span>
      ))}
    </span>
  );
};

export default ColourfulText; 