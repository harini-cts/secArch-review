#!/usr/bin/env python3
"""
Script to generate an Excel file with all security assessment questions
from the SecArch application questionnaires.
"""

import pandas as pd
import json
from app_web import SECURITY_QUESTIONNAIRES

def extract_all_questions():
    """Extract all questions from all security questionnaires"""
    all_questions = []
    
    for review_type, review_data in SECURITY_QUESTIONNAIRES.items():
        review_name = review_data.get('name', review_type)
        review_description = review_data.get('description', '')
        
        print(f"Processing {review_name}...")
        
        categories = review_data.get('categories', {})
        
        for category_key, category_data in categories.items():
            category_title = category_data.get('title', category_key)
            category_description = category_data.get('description', '')
            
            questions = category_data.get('questions', [])
            
            for question in questions:
                question_data = {
                    'Review Type': review_name,
                    'Review Description': review_description,
                    'Category': category_title,
                    'Category Description': category_description,
                    'Question ID': question.get('id', ''),
                    'Question': question.get('question', ''),
                    'Description': question.get('description', ''),
                    'Question Type': question.get('type', ''),
                    'Options': ', '.join(question.get('options', [])) if question.get('options') else '',
                    'ASVS Reference': question.get('asvs_reference', ''),
                    'OWASP Reference': question.get('owasp_reference', ''),
                    'Risk Level': question.get('risk_level', ''),
                    'Priority': question.get('priority', '')
                }
                all_questions.append(question_data)
    
    return all_questions

def create_excel_file(questions_data, filename='security_assessment_questions.xlsx'):
    """Create an Excel file with all questions organized by sheets"""
    
    # Create a DataFrame
    df = pd.DataFrame(questions_data)
    
    # Create Excel writer
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        
        # Main sheet with all questions
        df.to_excel(writer, sheet_name='All Questions', index=False)
        
        # Create separate sheets for each review type
        review_types = df['Review Type'].unique()
        
        for review_type in review_types:
            review_df = df[df['Review Type'] == review_type]
            
            # Clean sheet name (Excel sheet names have restrictions)
            sheet_name = review_type.replace(' ', '_')[:31]  # Max 31 chars
            sheet_name = ''.join(c for c in sheet_name if c.isalnum() or c in '_-')
            
            review_df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        # Create summary sheet
        summary_data = []
        for review_type in review_types:
            review_df = df[df['Review Type'] == review_type]
            categories = review_df['Category'].unique()
            
            for category in categories:
                category_df = review_df[review_df['Category'] == category]
                summary_data.append({
                    'Review Type': review_type,
                    'Category': category,
                    'Question Count': len(category_df),
                    'Description': category_df['Category Description'].iloc[0] if len(category_df) > 0 else ''
                })
        
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        # Create statistics sheet
        stats_data = []
        for review_type in review_types:
            review_df = df[df['Review Type'] == review_type]
            total_questions = len(review_df)
            categories_count = len(review_df['Category'].unique())
            
            stats_data.append({
                'Review Type': review_type,
                'Total Questions': total_questions,
                'Categories': categories_count,
                'Description': review_df['Review Description'].iloc[0] if len(review_df) > 0 else ''
            })
        
        stats_df = pd.DataFrame(stats_data)
        stats_df.to_excel(writer, sheet_name='Statistics', index=False)
    
    return filename

def main():
    """Main function to generate the Excel file"""
    print("🚀 Generating Security Assessment Questions Excel File...")
    print("=" * 60)
    
    # Extract all questions
    print("📊 Extracting questions from all questionnaires...")
    questions_data = extract_all_questions()
    
    print(f"✅ Found {len(questions_data)} total questions")
    
    # Create Excel file
    print("📝 Creating Excel file...")
    filename = create_excel_file(questions_data)
    
    print(f"✅ Excel file created successfully: {filename}")
    
    # Print summary
    print("\n📋 Summary:")
    print("-" * 40)
    
    review_types = {}
    for question in questions_data:
        review_type = question['Review Type']
        if review_type not in review_types:
            review_types[review_type] = 0
        review_types[review_type] += 1
    
    for review_type, count in review_types.items():
        print(f"  {review_type}: {count} questions")
    
    print(f"\n📁 File location: {filename}")
    print("🎉 Excel file generation completed!")

if __name__ == "__main__":
    main()
