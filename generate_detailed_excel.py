#!/usr/bin/env python3
"""
Enhanced script to generate a comprehensive Excel file with all security assessment questions
from the SecArch application questionnaires, including detailed metadata and analysis.
"""

import pandas as pd
import json
from datetime import datetime
from app_web import SECURITY_QUESTIONNAIRES

def extract_all_questions_detailed():
    """Extract all questions with detailed metadata from all security questionnaires"""
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
            
            for i, question in enumerate(questions, 1):
                # Determine question complexity based on description length and content
                complexity = "Low"
                if len(question.get('description', '')) > 100:
                    complexity = "High"
                elif len(question.get('description', '')) > 50:
                    complexity = "Medium"
                
                # Determine if it's a critical question based on keywords
                critical_keywords = ['authentication', 'authorization', 'encryption', 'data protection', 'access control', 'vulnerability', 'security']
                is_critical = any(keyword in question.get('question', '').lower() for keyword in critical_keywords)
                
                question_data = {
                    'Question Number': f"{review_type.upper()}-{category_key.upper()}-{i:03d}",
                    'Review Type': review_name,
                    'Review Description': review_description,
                    'Category': category_title,
                    'Category Description': category_description,
                    'Question ID': question.get('id', ''),
                    'Question': question.get('question', ''),
                    'Description': question.get('description', ''),
                    'Question Type': question.get('type', 'radio'),
                    'Options': ', '.join(question.get('options', [])) if question.get('options') else 'Yes, No, N/A',
                    'ASVS Reference': question.get('asvs_reference', ''),
                    'OWASP Reference': question.get('owasp_reference', ''),
                    'Risk Level': question.get('risk_level', 'Medium'),
                    'Priority': question.get('priority', 'Medium'),
                    'Complexity': complexity,
                    'Is Critical': 'Yes' if is_critical else 'No',
                    'Word Count': len(question.get('question', '').split()),
                    'Description Length': len(question.get('description', '')),
                    'Category Order': i,
                    'Review Order': len([q for q in all_questions if q['Review Type'] == review_name]) + 1
                }
                all_questions.append(question_data)
    
    return all_questions

def create_comprehensive_excel(questions_data, filename='security_assessment_questions_detailed.xlsx'):
    """Create a comprehensive Excel file with multiple sheets and analysis"""
    
    # Create Excel writer
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        
        # Main sheet with all questions
        df = pd.DataFrame(questions_data)
        df.to_excel(writer, sheet_name='All Questions', index=False)
        
        # Create separate sheets for each review type
        review_types = df['Review Type'].unique()
        
        for review_type in review_types:
            review_df = df[df['Review Type'] == review_type]
            
            # Clean sheet name
            sheet_name = review_type.replace(' ', '_')[:31]
            sheet_name = ''.join(c for c in sheet_name if c.isalnum() or c in '_-')
            
            review_df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        # Summary by review type
        summary_data = []
        for review_type in review_types:
            review_df = df[df['Review Type'] == review_type]
            categories = review_df['Category'].unique()
            
            critical_count = len(review_df[review_df['Is Critical'] == 'Yes'])
            high_complexity = len(review_df[review_df['Complexity'] == 'High'])
            
            summary_data.append({
                'Review Type': review_type,
                'Total Questions': len(review_df),
                'Categories': len(categories),
                'Critical Questions': critical_count,
                'High Complexity': high_complexity,
                'Avg Word Count': round(review_df['Word Count'].mean(), 1),
                'Description': review_df['Review Description'].iloc[0] if len(review_df) > 0 else ''
            })
        
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Review Summary', index=False)
        
        # Category breakdown
        category_data = []
        for review_type in review_types:
            review_df = df[df['Review Type'] == review_type]
            categories = review_df['Category'].unique()
            
            for category in categories:
                category_df = review_df[review_df['Category'] == category]
                critical_count = len(category_df[category_df['Is Critical'] == 'Yes'])
                
                category_data.append({
                    'Review Type': review_type,
                    'Category': category,
                    'Question Count': len(category_df),
                    'Critical Questions': critical_count,
                    'Avg Complexity': category_df['Complexity'].mode().iloc[0] if len(category_df) > 0 else 'Medium',
                    'Description': category_df['Category Description'].iloc[0] if len(category_df) > 0 else ''
                })
        
        category_df = pd.DataFrame(category_data)
        category_df.to_excel(writer, sheet_name='Category Breakdown', index=False)
        
        # Critical questions only
        critical_df = df[df['Is Critical'] == 'Yes']
        critical_df.to_excel(writer, sheet_name='Critical Questions', index=False)
        
        # High complexity questions
        complex_df = df[df['Complexity'] == 'High']
        complex_df.to_excel(writer, sheet_name='High Complexity', index=False)
        
        # Questions by type
        type_data = []
        for q_type in df['Question Type'].unique():
            type_df = df[df['Question Type'] == q_type]
            type_data.append({
                'Question Type': q_type,
                'Count': len(type_df),
                'Percentage': round(len(type_df) / len(df) * 100, 1)
            })
        
        type_df = pd.DataFrame(type_data)
        type_df.to_excel(writer, sheet_name='Question Types', index=False)
        
        # Risk level analysis
        risk_data = []
        for risk_level in df['Risk Level'].unique():
            risk_df = df[df['Risk Level'] == risk_level]
            risk_data.append({
                'Risk Level': risk_level,
                'Count': len(risk_df),
                'Percentage': round(len(risk_df) / len(df) * 100, 1),
                'Critical Questions': len(risk_df[risk_df['Is Critical'] == 'Yes'])
            })
        
        risk_df = pd.DataFrame(risk_data)
        risk_df.to_excel(writer, sheet_name='Risk Analysis', index=False)
        
        # Metadata sheet
        metadata = {
            'Generated On': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'Total Questions': len(df),
            'Total Reviews': len(review_types),
            'Total Categories': len(df['Category'].unique()),
            'Critical Questions': len(df[df['Is Critical'] == 'Yes']),
            'High Complexity Questions': len(df[df['Complexity'] == 'High']),
            'Average Questions per Review': round(len(df) / len(review_types), 1),
            'Average Questions per Category': round(len(df) / len(df['Category'].unique()), 1)
        }
        
        metadata_df = pd.DataFrame(list(metadata.items()), columns=['Metric', 'Value'])
        metadata_df.to_excel(writer, sheet_name='Metadata', index=False)
    
    return filename

def main():
    """Main function to generate the detailed Excel file"""
    print("🚀 Generating Detailed Security Assessment Questions Excel File...")
    print("=" * 70)
    
    # Extract all questions with detailed metadata
    print("📊 Extracting questions with detailed metadata...")
    questions_data = extract_all_questions_detailed()
    
    print(f"✅ Found {len(questions_data)} total questions")
    
    # Create comprehensive Excel file
    print("📝 Creating comprehensive Excel file...")
    filename = create_comprehensive_excel(questions_data)
    
    print(f"✅ Detailed Excel file created successfully: {filename}")
    
    # Print detailed summary
    print("\n📋 Detailed Summary:")
    print("-" * 50)
    
    df = pd.DataFrame(questions_data)
    
    review_types = df['Review Type'].unique()
    for review_type in review_types:
        review_df = df[df['Review Type'] == review_type]
        critical_count = len(review_df[review_df['Is Critical'] == 'Yes'])
        high_complexity = len(review_df[review_df['Complexity'] == 'High'])
        
        print(f"  {review_type}:")
        print(f"    Total Questions: {len(review_df)}")
        print(f"    Critical Questions: {critical_count}")
        print(f"    High Complexity: {high_complexity}")
        print(f"    Categories: {len(review_df['Category'].unique())}")
        print()
    
    print(f"📁 File location: {filename}")
    print("🎉 Detailed Excel file generation completed!")
    print("\n📊 Excel file contains the following sheets:")
    print("  - All Questions: Complete list of all questions")
    print("  - Review Summary: Summary by review type")
    print("  - Category Breakdown: Questions by category")
    print("  - Critical Questions: Only critical security questions")
    print("  - High Complexity: Complex questions requiring detailed analysis")
    print("  - Question Types: Analysis by question type")
    print("  - Risk Analysis: Questions grouped by risk level")
    print("  - Metadata: Generation statistics and metrics")

if __name__ == "__main__":
    main()
