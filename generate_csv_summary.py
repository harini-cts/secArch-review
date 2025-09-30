#!/usr/bin/env python3
"""
Script to generate CSV files and a summary document for all security assessment questions.
"""

import pandas as pd
import json
from datetime import datetime
from app_web import SECURITY_QUESTIONNAIRES

def generate_csv_files():
    """Generate CSV files for different views of the questions"""
    
    # Extract all questions
    all_questions = []
    
    for review_type, review_data in SECURITY_QUESTIONNAIRES.items():
        review_name = review_data.get('name', review_type)
        review_description = review_data.get('description', '')
        
        categories = review_data.get('categories', {})
        
        for category_key, category_data in categories.items():
            category_title = category_data.get('title', category_key)
            category_description = category_data.get('description', '')
            
            questions = category_data.get('questions', [])
            
            for i, question in enumerate(questions, 1):
                question_data = {
                    'Question_Number': f"{review_type.upper()}-{category_key.upper()}-{i:03d}",
                    'Review_Type': review_name,
                    'Category': category_title,
                    'Question_ID': question.get('id', ''),
                    'Question': question.get('question', ''),
                    'Description': question.get('description', ''),
                    'Question_Type': question.get('type', 'radio'),
                    'Options': ', '.join(question.get('options', [])) if question.get('options') else 'Yes, No, N/A',
                    'ASVS_Reference': question.get('asvs_reference', ''),
                    'OWASP_Reference': question.get('owasp_reference', ''),
                    'Risk_Level': question.get('risk_level', 'Medium'),
                    'Priority': question.get('priority', 'Medium')
                }
                all_questions.append(question_data)
    
    # Create main CSV
    df = pd.DataFrame(all_questions)
    df.to_csv('security_assessment_questions.csv', index=False)
    
    # Create CSV for each review type
    for review_type in df['Review_Type'].unique():
        review_df = df[df['Review_Type'] == review_type]
        filename = f"questions_{review_type.lower().replace(' ', '_')}.csv"
        review_df.to_csv(filename, index=False)
    
    return df

def generate_summary_document(df):
    """Generate a markdown summary document"""
    
    summary_content = f"""# Security Assessment Questions Summary

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overview

This document provides a comprehensive summary of all security assessment questions used in the SecArch application. The questions are organized by review type and category, following ASVS (Application Security Verification Standard) guidelines.

## Statistics

- **Total Questions**: {len(df)}
- **Review Types**: {len(df['Review_Type'].unique())}
- **Categories**: {len(df['Category'].unique())}
- **Average Questions per Review**: {len(df) / len(df['Review_Type'].unique()):.1f}

## Review Types Breakdown

"""
    
    for review_type in df['Review_Type'].unique():
        review_df = df[df['Review_Type'] == review_type]
        categories = review_df['Category'].unique()
        
        summary_content += f"""### {review_type}

- **Total Questions**: {len(review_df)}
- **Categories**: {len(categories)}
- **Description**: {review_df['Review_Description'].iloc[0] if 'Review_Description' in review_df.columns else 'N/A'}

**Categories:**
"""
        for category in categories:
            category_df = review_df[review_df['Category'] == category]
            summary_content += f"- {category}: {len(category_df)} questions\n"
        
        summary_content += "\n"
    
    summary_content += """## Question Types

"""
    
    for q_type in df['Question_Type'].unique():
        type_df = df[df['Question_Type'] == q_type]
        percentage = len(type_df) / len(df) * 100
        summary_content += f"- **{q_type}**: {len(type_df)} questions ({percentage:.1f}%)\n"
    
    summary_content += f"""

## Risk Level Distribution

"""
    
    for risk_level in df['Risk_Level'].unique():
        risk_df = df[df['Risk_Level'] == risk_level]
        percentage = len(risk_df) / len(df) * 100
        summary_content += f"- **{risk_level}**: {len(risk_df)} questions ({percentage:.1f}%)\n"
    
    summary_content += f"""

## Files Generated

1. **security_assessment_questions.xlsx** - Complete Excel file with multiple sheets
2. **security_assessment_questions_detailed.xlsx** - Enhanced Excel file with analysis
3. **security_assessment_questions.csv** - Main CSV file with all questions
4. **questions_[review_type].csv** - Individual CSV files for each review type

## Usage

These questions are used in the SecArch security assessment portal to:

1. **Personalize Assessments**: Questions are filtered based on application technology stack
2. **Comprehensive Coverage**: Cover all major security domains (ASVS-based)
3. **Risk-Based Approach**: Questions are prioritized by risk level and criticality
4. **Flexible Format**: Support multiple question types and response options

## Standards Compliance

- **ASVS (Application Security Verification Standard)**: Primary security framework
- **OWASP Top 10**: Web application security risks
- **OWASP Cloud Top 10**: Cloud-specific security risks
- **Industry Best Practices**: Security controls and recommendations

## Question Structure

Each question includes:
- Unique identifier
- Clear question text
- Detailed description/context
- Response options (typically Yes/No/N/A)
- Security standard references
- Risk level and priority
- Category classification

---

*This summary is automatically generated from the SecArch application's security questionnaire definitions.*
"""
    
    with open('security_questions_summary.md', 'w', encoding='utf-8') as f:
        f.write(summary_content)
    
    return 'security_questions_summary.md'

def main():
    """Main function to generate CSV files and summary"""
    print("🚀 Generating CSV Files and Summary Document...")
    print("=" * 60)
    
    # Generate CSV files
    print("📊 Generating CSV files...")
    df = generate_csv_files()
    
    print(f"✅ Generated main CSV: security_assessment_questions.csv")
    print(f"✅ Generated {len(df['Review_Type'].unique())} review-specific CSV files")
    
    # Generate summary document
    print("📝 Generating summary document...")
    summary_file = generate_summary_document(df)
    
    print(f"✅ Generated summary: {summary_file}")
    
    print("\n📁 Files created:")
    print("  - security_assessment_questions.csv")
    print("  - questions_application_security_review.csv")
    print("  - questions_cloud_security_review.csv")
    print("  - questions_database_security_review.csv")
    print("  - questions_infrastructure_security_review.csv")
    print("  - questions_compliance_security_review.csv")
    print("  - questions_api_security_review.csv")
    print(f"  - {summary_file}")
    
    print("\n🎉 CSV and summary generation completed!")

if __name__ == "__main__":
    main()
