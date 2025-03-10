"use client";

import { useState, useCallback } from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

type Tab = {
  title: string;
  value: string;
  content?: string | React.ReactNode | any;
};

export const Tabs = ({
  tabs: propTabs,
  containerClassName,
  activeTabClassName,
  tabClassName,
  contentClassName,
  onValueChange,
  currentRoute, // New prop to sync with current page
}: {
  tabs: Tab[];
  containerClassName?: string;
  activeTabClassName?: string;
  tabClassName?: string;
  contentClassName?: string;
  onValueChange?: (value: string) => void;
  currentRoute?: string;
}) => {
  // Set initial active tab based on current route, fallback to first tab
  const initialActiveTab =
    propTabs.find((tab) => tab.value === currentRoute) || propTabs[0];
  const [active, setActive] = useState<Tab>(initialActiveTab);
  const [hoveredTab, setHoveredTab] = useState<string | null>(null);
  const [tabs, setTabs] = useState<Tab[]>(propTabs);
  const [hovering, setHovering] = useState(false);

  // Debounce hover updates
  const debounce = (func: (...args: any[]) => void, wait: number) => {
    let timeout: NodeJS.Timeout;
    return (...args: any[]) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => func(...args), wait);
    };
  };

  const debouncedSetHoveredTab = useCallback(
    debounce((value: string | null) => {
      setHoveredTab(value);
    }, 50),
    []
  );

  const moveSelectedTabToTop = (idx: number) => {
    const newTabs = [...propTabs];
    const selectedTab = newTabs.splice(idx, 1);
    newTabs.unshift(selectedTab[0]);
    setTabs(newTabs);
    setActive(newTabs[0]);
    setHoveredTab(null); // Clear hover on click
    onValueChange?.(newTabs[0].value);
  };

  // Highlight follows hover, falls back to active (current page)
  const highlightedTab = hoveredTab || active.value;

  return (
    <div
      className={cn(
        "flex flex-row items-center justify-start [perspective:1000px] relative overflow-auto sm:overflow-visible no-visible-scrollbar max-w-full w-full",
        containerClassName
      )}
      onMouseLeave={() => {
        debouncedSetHoveredTab(null); // Reset hover when leaving the container
        setHovering(false);
      }}
    >
      {propTabs.map((tab, idx) => (
        <button
          key={tab.title}
          onClick={() => moveSelectedTabToTop(idx)}
          onMouseEnter={() => {
            debouncedSetHoveredTab(tab.value);
            setHovering(true);
          }}
          onMouseLeave={() => {
            // No need to reset here; handled by container onMouseLeave
          }}
          className={cn("relative px-4 py-2 rounded-full", tabClassName)}
          style={{
            transformStyle: "preserve-3d",
          }}
        >
          {highlightedTab === tab.value && (
            <motion.div
              layoutId="tab-highlight"
              transition={{
                type: "spring",
                stiffness: 400,
                damping: 40,
                mass: 0.5,
              }}
              className={cn(
                "absolute inset-0 bg-gray-200 dark:bg-zinc-800 rounded-full",
                activeTabClassName
              )}
            />
          )}

          <span className="relative block text-black dark:text-white">
            {tab.title}
          </span>
        </button>
      ))}
      <FadeInDiv
        tabs={tabs}
        active={active}
        key={active.value}
        hovering={hovering}
        className={cn("mt-32", contentClassName)}
      />
    </div>
  );
};

export const FadeInDiv = ({
  className,
  tabs,
  hovering,
}: {
  className?: string;
  key?: string;
  tabs: Tab[];
  active: Tab;
  hovering?: boolean;
}) => {
  const isActive = (tab: Tab) => {
    return tab.value === tabs[0].value;
  };
  return (
    <div className="relative w-full h-full">
      {tabs.map((tab, idx) => (
        <motion.div
          key={tab.value}
          layoutId={tab.value}
          style={{
            scale: 1 - idx * 0.1,
            top: hovering ? idx * -50 : 0,
            zIndex: -idx,
            opacity: idx < 3 ? 1 - idx * 0.1 : 0,
          }}
          animate={{
            y: isActive(tab) ? [0, 40, 0] : 0,
          }}
          className={cn("w-full h-full absolute top-0 left-0", className)}
        >
          {tab.content}
        </motion.div>
      ))}
    </div>
  );
};