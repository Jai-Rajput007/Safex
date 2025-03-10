"use client";
import {
  Navbar as HeroUINavbar,
  NavbarContent,
  NavbarMenu,
  NavbarMenuToggle,
  NavbarBrand,
  NavbarItem,
} from "@heroui/navbar";
import { Link } from "@heroui/link";
import { LinkedInIcon, GithubIcon, DiscordIcon, Logo } from "@/components/icons";
import NextLink from "next/link";
import clsx from "clsx";
import { useRouter } from "next/navigation";
import { siteConfig } from "@/config/site";
import Switch from "./Switch";
import { Tabs } from "./ui/tabs";
import { useEffect } from "react";

export const Navbar = () => {
  const router = useRouter();

  const navTabs = siteConfig.navItems.map((item) => ({
    title: item.label,
    value: item.href,
    content: <div>{item.label} Content</div>,
  }));

  const handleTabChange = (value: string) => {
    router.push(value);
  };

  const currentRoute = router.asPath;

  return (
    <HeroUINavbar
      maxWidth="xl"
      position="sticky"
      shouldHideOnScroll
      className="bg-opacity-70 bg-white dark:bg-[#1a0123] dark:bg-opacity-70 transition-all duration-300 ease-in-out shadow-[0_4px_10px_-1px_rgba(147,51,234,0.5)] dark:shadow-[0_4px_10px_-1px_rgba(147,51,234,0.7)]"
    >
      <NavbarContent className="basis-1/5 sm:basis-full" justify="start">
        <NavbarBrand as="li" className="gap-3 max-w-fit">
          <NextLink className="flex justify-start items-center gap-1" href="/">
            <Logo />
            <p className="font-bold text-inherit">SAFEX</p>
          </NextLink>
        </NavbarBrand>

        <nav className="hidden lg:flex ml-2">
          <Tabs
            tabs={navTabs}
            containerClassName="flex items-center gap-2"
            tabClassName="text-sm font-medium text-white dark:text-gray-300 hover:bg-[#00b7ff] dark:hover:bg-[#7828c8] hover:text-white dark:hover:text-white px-4 py-1.5 rounded-full transition-colors duration-400 ease-in-out min-w-[80px] text-center bg-transparent"
            activeTabClassName="bg-[#00b7ff] dark:bg-[#7828c8] text-white dark:text-white rounded-full transition-colors duration-400 ease-in-out min-w-[80px] text-center px-4 py-1.5"
            contentClassName="hidden"
            onValueChange={handleTabChange}
            currentRoute={currentRoute}
          />
        </nav>
      </NavbarContent>

      <NavbarContent
        className="hidden sm:flex basis-1/5 sm:basis-full"
        justify="end"
      >
        <NavbarItem className="hidden sm:flex gap-2">
          <Link
            isExternal
            aria-label="LinkedIn"
            href={siteConfig.links.linkedin}
          >
            <LinkedInIcon className="text-default-500" />
          </Link>
          <Link isExternal aria-label="Discord" href={siteConfig.links.discord}>
            <DiscordIcon className="text-default-500" />
          </Link>
          <Link isExternal aria-label="Github" href={siteConfig.links.github}>
            <GithubIcon className="text-default-500" />
          </Link>
          <Switch />
        </NavbarItem>
      </NavbarContent>

      <NavbarContent className="sm:hidden basis-1 pl-4" justify="end">
        <Link isExternal aria-label="Github" href={siteConfig.links.github}>
          <GithubIcon className="text-default-500" />
        </Link>
        <Switch />
        <NavbarMenuToggle />
      </NavbarContent>

      <NavbarMenu>
        <div className="mx-4 mt-2 flex flex-col gap-2">
          {siteConfig.navMenuItems.map((item, index) => (
            <NavbarItem key={`${item.label}-${index}`}>
              <Link
                color={
                  index === 2
                    ? "primary"
                    : index === siteConfig.navMenuItems.length - 1
                    ? "danger"
                    : "foreground"
                }
                href={item.href}
                size="lg"
              >
                {item.label}
              </Link>
            </NavbarItem>
          ))}
        </div>
      </NavbarMenu>
    </HeroUINavbar>
  );
};