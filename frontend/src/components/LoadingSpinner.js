import React from 'react';

const LoadingSpinner = ({ size = 'lg', text = 'Loading...' }) => {
  const sizeClasses = {
    sm: 'w-6 h-6',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16',
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-64 space-y-4">
      <div className={`${sizeClasses[size]} animate-spin`}>
        <div className="border-4 border-gray-200 border-t-4 border-t-blue-600 rounded-full w-full h-full"></div>
      </div>
      <p className="text-gray-600 text-sm">{text}</p>
    </div>
  );
};

export default LoadingSpinner;