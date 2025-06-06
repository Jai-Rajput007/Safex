'use client';
import React from 'react';

export const Button = () => {
  return (
    <div>
      <button className="group flex items-center font-medium text-lg py-3 px-5 text-white bg-gradient-to-r from-blue-700 via-purple-800 to-pink-700 border-none rounded-2xl cursor-pointer">
        <svg 
          xmlns="http://www.w3.org/2000/svg" 
          viewBox="0 0 24 24" 
          width={24} 
          height={24}
          className="mr-1 transform rotate-30 transition-transform duration-500 ease-in-out group-hover:translate-x-1 group-hover:rotate-90"
        >
          <path fill="none" d="M0 0h24v24H0z" />
          <path 
            fill="currentColor" 
            d="M5 13c0-5.088 2.903-9.436 7-11.182C16.097 3.564 19 7.912 19 13c0 .823-.076 1.626-.22 2.403l1.94 1.832a.5.5 0 0 1 .095.603l-2.495 4.575a.5.5 0 0 1-.793.114l-2.234-2.234a1 1 0 0 0-.707-.293H9.414a1 1 0 0 0-.707.293l-2.234 2.234a.5.5 0 0 1-.793-.114l-2.495-4.575a.5.5 0 0 1 .095-.603l1.94-1.832C5.077 14.626 5 13.823 5 13zm1.476 6.696l.817-.817A3 3 0 0 1 9.414 18h5.172a3 3 0 0 1 2.121.879l.817.817.982-1.8-1.1-1.04a2 2 0 0 1-.593-1.82c.124-.664.187-1.345.187-2.036 0-3.87-1.995-7.3-5-8.96C8.995 5.7 7 9.13 7 13c0 .691.063 1.372.187 2.037a2 2 0 0 1-.593 1.82l-1.1 1.039.982 1.8zM12 13a2 2 0 1 1 0-4 2 2 0 0 1 0 4z" 
          />
        </svg>
        <span className="transition-transform duration-500 ease-in-out group-hover:translate-x-2">
          Let's Try
        </span>
      </button>
    </div>
  );
};

// Also export as default for backwards compatibility
export default Button;