/**
 * AI Content Formatting Utilities
 * Provides consistent formatting for AI-generated content across the application
 */

import React from 'react';

/**
 * Converts AI analysis text to structured bullet points
 * @param {string} text - The AI analysis text to format
 * @returns {Array} Array of sections with headers and bullet points
 */
export const convertTextToBulletPoints = (text) => {
  if (!text) return [];

  const lines = text.split('\n').filter(line => line.trim());
  const bulletPoints = [];
  let currentSection = null;
  
  lines.forEach(line => {
    const trimmedLine = line.trim();
    if (!trimmedLine) return;

    // Check for section headers (lines with emojis, numbers, or keywords)
    if (trimmedLine.match(/^[📊🎯💡\d]/) || 
        trimmedLine.toLowerCase().includes('analysis') ||
        trimmedLine.toLowerCase().includes('insights') ||
        trimmedLine.toLowerCase().includes('summary') ||
        trimmedLine.toLowerCase().includes('recommendation')) {
      
      // This is a section header
      currentSection = {
        header: trimmedLine,
        points: []
      };
      bulletPoints.push(currentSection);
    } else {
      // This is content - convert to bullet point
      if (currentSection) {
        // Split long sentences into multiple bullet points
        const sentences = trimmedLine.split(/[.!?]+/).filter(s => s.trim().length > 10);
        sentences.forEach(sentence => {
          const cleanSentence = sentence.trim();
          if (cleanSentence) {
            currentSection.points.push(cleanSentence);
          }
        });
      } else {
        // No section header yet, create a general section
        if (bulletPoints.length === 0) {
          currentSection = {
            header: '📊 Financial Insights',
            points: []
          };
          bulletPoints.push(currentSection);
        }
        const sentences = trimmedLine.split(/[.!?]+/).filter(s => s.trim().length > 10);
        sentences.forEach(sentence => {
          const cleanSentence = sentence.trim();
          if (cleanSentence) {
            bulletPoints[0].points.push(cleanSentence);
          }
        });
      }
    }
  });

  return bulletPoints;
};

/**
 * Formats bullet points for display in AI chat messages
 * @param {Array} bulletPoints - Array of sections with headers and points
 * @returns {string} Formatted markdown text for chat display
 */
export const formatBulletPointsForChat = (bulletPoints) => {
  if (!bulletPoints || bulletPoints.length === 0) return '';

  return bulletPoints.map(section => {
    const header = `**${section.header}**\n`;
    const points = section.points.map(point => `• ${point}`).join('\n');
    return `${header}${points}`;
  }).join('\n\n');
};

/**
 * Formats bullet points for display in React components
 * @param {Array} bulletPoints - Array of sections with headers and points
 * @param {boolean} isPreview - Whether this is a preview (limited content)
 * @returns {JSX.Element[]} Array of React elements
 */
export const formatBulletPointsToJSX = (bulletPoints, isPreview = false) => {
  if (!bulletPoints || bulletPoints.length === 0) return [];

  return bulletPoints.map((section, sectionIndex) => (
    <div key={sectionIndex} className="ai-bullet-section">
      {/* Section Header */}
      <div className="ai-bullet-header ai-typewriter-font">
        {section.header}
      </div>
      
      {/* Bullet Points */}
      <ul className="ai-bullet-list">
        {section.points.map((point, pointIndex) => (
          <li key={pointIndex} className="ai-bullet-item">
            <span className="ai-bullet-marker">•</span>
            <span className="ai-bullet-text ai-typewriter-font">{point}</span>
          </li>
        ))}
        {isPreview && section.points.length > 0 && (
          <li className="ai-bullet-item">
            <span className="ai-bullet-marker text-gray-400">•</span>
            <span className="ai-bullet-text text-gray-500 dark:text-gray-400 italic">
              View full analysis for more insights...
            </span>
          </li>
        )}
      </ul>
    </div>
  ));
};

/**
 * Formats AI insights as natural paragraphs for better readability
 * @param {string} text - The AI analysis text
 * @param {boolean} isPreview - Whether to show preview version (limited content)
 * @returns {JSX.Element[]} Formatted React elements in paragraph style
 */
export const formatInsightsAsParagraphs = (text, isPreview = false) => {
  if (!text) return [];

  // Split text into paragraphs and clean up
  const paragraphs = text.split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0);

  let displayParagraphs;

  if (isPreview) {
    // In preview mode, find the first complete section (header + content)
    let sectionFound = false;
    let headerIndex = -1;

    // Find the first header
    for (let i = 0; i < paragraphs.length; i++) {
      const isHeader = paragraphs[i].match(/^[📊🎯💡\d]/) ||
                      paragraphs[i].toLowerCase().includes('analysis') ||
                      paragraphs[i].toLowerCase().includes('insights') ||
                      paragraphs[i].toLowerCase().includes('summary') ||
                      paragraphs[i].toLowerCase().includes('recommendation');

      if (isHeader) {
        headerIndex = i;
        break;
      }
    }

    if (headerIndex !== -1) {
      // Include the header and the next paragraph (if it exists)
      const endIndex = Math.min(headerIndex + 2, paragraphs.length);
      displayParagraphs = paragraphs.slice(headerIndex, endIndex);
    } else {
      // No header found, just show first paragraph
      displayParagraphs = paragraphs.slice(0, 1);
    }
  } else {
    displayParagraphs = paragraphs;
  }

  return displayParagraphs.map((paragraph, index) => {
    // Check if this is a header line (contains emojis or specific keywords)
    const isHeader = paragraph.match(/^[📊🎯💡\d]/) ||
                    paragraph.toLowerCase().includes('analysis') ||
                    paragraph.toLowerCase().includes('insights') ||
                    paragraph.toLowerCase().includes('summary') ||
                    paragraph.toLowerCase().includes('recommendation');

    if (isHeader) {
      return (
        <div key={index} className="ai-section-header">
          <h4 className="text-sm font-semibold text-gray-800 dark:text-gray-200 mb-2 ai-typewriter-font">
            {paragraph}
          </h4>
        </div>
      );
    } else {
      return (
        <div key={index} className="ai-paragraph">
          <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed mb-3 ai-typewriter-font">
            {paragraph}
          </p>
        </div>
      );
    }
  });
};

/**
 * Main function to format AI insights with bullet points for widget display
 * @param {string} text - The AI analysis text
 * @param {boolean} isPreview - Whether to show preview version (limited content)
 * @returns {JSX.Element[]} Formatted React elements
 */
export const formatInsightsToBulletPoints = (text, isPreview = false) => {
  if (!text) return [];

  const bulletPoints = convertTextToBulletPoints(text);

  // If preview mode, limit content
  if (isPreview) {
    const limitedBulletPoints = bulletPoints.slice(0, 1); // Show only first section
    if (limitedBulletPoints[0]) {
      limitedBulletPoints[0].points = limitedBulletPoints[0].points.slice(0, 3); // Show only first 3 points
    }
    return formatBulletPointsToJSX(limitedBulletPoints, true);
  }

  return formatBulletPointsToJSX(bulletPoints, false);
};
